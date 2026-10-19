"""The secure profile binds every permit to its presenter (ADR 0028).

External review, 19 October 2026, finding 4: the secure profile did not
require presenter keys, so it minted spec 0.1 permits that anyone holding
the bytes could present. A receiver with default settings (ADR 0027) refuses
those.

Claims -> tests:
  - Under the secure profile the API does not start without
    PV_PRESENTER_BUNDLE, or with one for another organisation
    -> test_secure_profile_needs_a_presenter_bundle,
       test_presenter_bundle_must_match_the_issuer
  - init_secure_profile issues a client CA and one client certificate per
    API-key holder (0600 keys, clientAuth, chained to the CA) and pins each
    key; --replace-existing rotates them
    -> test_provision_issues_and_pins_client_certificates,
       test_replace_existing_rotates_client_certificates
  - A secure mint without the agent's own presenter is refused; with it the
    permit binds the presenter (spec 0.2)
    -> test_secure_mint_requires_the_agents_own_presenter
  - That permit is admitted by a default receiver only from the agent's
    certificate, and the provisioned CA is what a real mTLS gate accepts
    -> test_default_receiver_admits_only_the_bound_agent,
       test_provisioned_certificates_pass_a_real_mtls_gate
"""

from __future__ import annotations

import importlib
import json
import os
import socket
import ssl
import stat
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from agent_dna.authority_v01 import sha256_digest
from agent_dna.presenter_identity import certificate_der_from_file
from agent_dna.receiver.gate import ReceiverGate
from agent_dna.receiver.ledger import ReceiverLedger
from agent_dna.receiver.permit_header import PERMIT_HEADER, encode_permit_header
from tests.decide_binding import execution_action_for
from tests.test_authorize_mint_claim import AGENT, ORG, _authorize_body, _dispatch
from tests.test_init_secure_profile import _load_env, presenter_digest
from tests.test_operation_registry import PAY, _pay, _secure
from tools.init_secure_profile import OPERATOR, provision

WIRE = b'{"amount":100}'


def _mint_body(decided, presenter=None):
    record = decided.json()["record"]
    action = execution_action_for(
        AGENT, "payments.pay_invoice", {"amount": 100}, resource="vendor:V-100", org=ORG
    )
    body = _authorize_body(
        record,
        wire=WIRE,
        dispatch=_dispatch(
            destination="payments.partner.example",
            operation="POST /api/v1/transfers",
            credential_audience="payments.partner.example",
        ),
        action=action,
    )
    for name in (
        "policy_bundle_digest",
        "authority_receipt_digest",
        "state_snapshot_digest",
        "obligations_digest",
    ):
        body.pop(name)
    if presenter is not None:
        body["presenter_identity_digest"] = presenter
    body["security_events"] = [
        {
            "spec": "pv-agent-security-event/1.0",
            "event_id": f"presenter-event-{presenter}",
            "trace_id": decided.json()["execution_id"],
            "occurred_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source_agent_id": AGENT,
            "target_agent_id": "payments.partner.example",
            "relation": "INVOKES",
            "action_digest": sha256_digest(action),
            "authorization_id": record["decision_id"],
            "authorization_state": "VERIFIED",
            "parent_event_id": None,
        }
    ]
    return body


def _start(server):
    importlib.reload(server)
    server._pv_signer_cache.clear()
    with TestClient(server.app):
        pass


# ---- start-up ----------------------------------------------------------------------


def test_secure_profile_needs_a_presenter_bundle(tmp_path, monkeypatch):
    server, _key, _out = _secure(tmp_path, monkeypatch, operations=[PAY])
    monkeypatch.delenv("PV_PRESENTER_BUNDLE")
    with pytest.raises(RuntimeError, match="PV_PRESENTER_BUNDLE"):
        _start(server)
    monkeypatch.setenv("PV_PRESENTER_BUNDLE", str(tmp_path / "missing.json"))
    with pytest.raises(RuntimeError, match="path does not exist"):
        _start(server)


def test_presenter_bundle_must_match_the_issuer(tmp_path, monkeypatch):
    server, _key, out = _secure(tmp_path, monkeypatch, operations=[PAY])
    bundle = json.loads((out / "presenter-bundle.json").read_text())
    bundle["organisation_id"] = "someone-else.example"
    other = tmp_path / "other-presenters.json"
    other.write_text(json.dumps(bundle))
    monkeypatch.setenv("PV_PRESENTER_BUNDLE", str(other))
    with pytest.raises(RuntimeError, match="someone-else.example"):
        _start(server)


# ---- provisioning --------------------------------------------------------------------


def _cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def test_provision_issues_and_pins_client_certificates(tmp_path, monkeypatch):
    out = tmp_path / "secure"
    provision(
        out,
        org=ORG,
        agents=[AGENT],
        grants=[{"agent_id": AGENT, "capability": "payments.pay_invoice"}],
    )
    env = _load_env(out / "secure.env", monkeypatch)
    assert env["PV_PRESENTER_BUNDLE"] == str(out / "presenter-bundle.json")
    presenters = out / "presenters"
    assert stat.S_IMODE(presenters.stat().st_mode) == 0o700
    ca = _cert(presenters / "client-ca.pem")
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert stat.S_IMODE((presenters / "client-ca.key").stat().st_mode) == 0o600
    bundle = json.loads((out / "presenter-bundle.json").read_text())
    assert bundle["organisation_id"] == ORG
    assert set(bundle["presenters"]) == {OPERATOR, AGENT}
    for agent in (OPERATOR, AGENT):
        cert = _cert(presenters / f"{agent}.pem")
        cert.verify_directly_issued_by(ca)
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        assert list(eku) == [ExtendedKeyUsageOID.CLIENT_AUTH]
        assert not cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value.ca
        assert stat.S_IMODE((presenters / f"{agent}.key").stat().st_mode) == 0o600
        assert bundle["presenters"][agent] == [presenter_digest(out, agent)]
    assert presenter_digest(out, OPERATOR) != presenter_digest(out, AGENT)


def test_replace_existing_rotates_client_certificates(tmp_path):
    out = tmp_path / "secure"
    provision(out, org=ORG, agents=[AGENT], grants=[])
    before = presenter_digest(out, AGENT)
    stray = out / "presenters" / "note.txt"
    stray.write_text("x")
    provision(out, org=ORG, agents=[AGENT], grants=[], replace_existing=True)
    assert presenter_digest(out, AGENT) != before
    assert not stray.exists()
    (out / "presenters" / "nested").mkdir()
    with pytest.raises(ValueError, match="unexpected subdirectory"):
        provision(out, org=ORG, agents=[AGENT], grants=[], replace_existing=True)


# ---- minting and admission -----------------------------------------------------------


def test_secure_mint_requires_the_agents_own_presenter(tmp_path, monkeypatch):
    server, key, out = _secure(tmp_path, monkeypatch, operations=[PAY])
    with TestClient(server.app) as client:
        decided = _pay(client, key, 100)
        assert decided.status_code == 200, decided.text

        def mint(presenter):
            return client.post(
                "/v1/authorize",
                headers={"X-API-Key": key},
                json=_mint_body(decided, presenter),
            )

        missing = mint(None)
        assert missing.status_code == 403
        assert missing.json()["detail"]["reason_code"] == "AUTHORIZE_PRESENTER_REQUIRED"
        borrowed = mint(presenter_digest(out, OPERATOR))
        assert borrowed.status_code == 403
        assert (
            borrowed.json()["detail"]["reason_code"] == "AUTHORIZE_PRESENTER_NOT_PINNED"
        )
        own = mint(presenter_digest(out, AGENT))
        assert own.status_code == 200, own.text
        permit = own.json()["authorization"]
        assert permit["expected_presenter_identity_digest"] == presenter_digest(
            out, AGENT
        )
        assert permit["spec"] == "pv-execution-authorization/0.2-experimental"
        runtime = client.get("/v1/runtime", headers={"X-API-Key": key}).json()
        assert (
            "presenter bundle required"
            in (runtime["composition"]["secure_profile"]["detail"])
        )


def test_default_receiver_admits_only_the_bound_agent(tmp_path, monkeypatch):
    server, key, out = _secure(tmp_path, monkeypatch, operations=[PAY])
    with TestClient(server.app) as client:
        decided = _pay(client, key, 100)
        minted = client.post(
            "/v1/authorize",
            headers={"X-API-Key": key},
            json=_mint_body(decided, presenter_digest(out, AGENT)),
        )
        assert minted.status_code == 200, minted.text
    permit = minted.json()["authorization"]
    gate = ReceiverGate(
        receiver_id="payments.partner.example",
        destinations=frozenset({"payments.partner.example"}),
        trust_bundle=json.loads((out / "trust-bundle.json").read_text()),
        ledger=ReceiverLedger(tmp_path / "receiver.db"),
        receipt_signing_key=SigningKey.generate(),
        receipt_key_id="receiver-01",
        require_presenter=True,  # the receiver kit's default with mTLS
    )

    def present(cert_der):
        return gate.check(
            method="POST",
            path="/api/v1/transfers",
            headers={
                PERMIT_HEADER: encode_permit_header(permit),
                "Content-Type": "application/json",
            },
            body=WIRE,
            presenter_certificate=cert_der,
        )

    pem = out / "presenters"
    assert not present(None).admitted
    assert not present(certificate_der_from_file(pem / f"{OPERATOR}.pem")).admitted
    admitted = present(certificate_der_from_file(pem / f"{AGENT}.pem"))
    assert admitted.admitted, admitted


def test_provisioned_certificates_pass_a_real_mtls_gate(tmp_path):
    """The receiver kit's server, with the provisioned client CA as
    PV_RECEIVER_CLIENT_CA, accepts the agent's certificate and nothing
    without one."""
    from tests.network.test_receiver_kit import _env
    from tests.receiver._pki import Pki

    out = tmp_path / "secure"
    provision(out, org=ORG, agents=[AGENT], grants=[])
    server_pki = Pki(tmp_path / "server-pki")  # the receiver's own server CA
    gate_leaf = server_pki.leaf("gate", server=True)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    env = _env(
        tmp_path,
        SigningKey.generate(),
        SigningKey.generate(),
        PV_RECEIVER_TLS_CERT=str(gate_leaf.cert),
        PV_RECEIVER_TLS_KEY=str(gate_leaf.key),
        PV_RECEIVER_CLIENT_CA=str(out / "presenters" / "client-ca.pem"),
        PV_RECEIVER_ALLOW_PLAINTEXT="",
        PV_RECEIVER_HOST="127.0.0.1",
        PV_RECEIVER_PORT=str(port),
    )
    proc = subprocess.Popen(
        [sys.executable, "-m", "network.receiver_kit.serve"],
        env={**{k: v for k, v in os.environ.items() if not k.startswith("PV_")}, **env},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    def post(with_cert: bool) -> int:
        import http.client

        ctx = ssl.create_default_context(cafile=str(server_pki.ca_cert))
        if with_cert:
            ctx.load_cert_chain(
                str(out / "presenters" / f"{AGENT}.pem"),
                str(out / "presenters" / f"{AGENT}.key"),
            )
        conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=5)
        try:
            conn.request("POST", "/api/v1/transfers", body=WIRE)
            return conn.getresponse().status
        finally:
            conn.close()

    try:
        deadline = time.monotonic() + 20
        while True:
            try:
                status = post(with_cert=True)
                break
            except (ConnectionRefusedError, ssl.SSLError, OSError) as exc:
                if proc.poll() is not None or time.monotonic() > deadline:
                    raise AssertionError(
                        proc.stdout.read().decode() if proc.stdout else ""
                    ) from exc
                time.sleep(0.2)
        assert status == 403  # reached the gate: no permit, refused
        with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
            post(with_cert=False)
    finally:
        proc.terminate()
        proc.communicate(timeout=10)


# ---- the Helm chart ---------------------------------------------------------------

CHART = Path(__file__).resolve().parents[1] / "deploy" / "helm" / "privatevault"


def test_chart_requires_a_presenter_bundle_with_the_secure_profile():
    """Rendered for real by CI's helm job (lint, template, check-refusals,
    kind e2e); this pins the wiring those runs depend on."""
    import yaml

    helpers = (CHART / "templates" / "_helpers.tpl").read_text()
    assert (
        "if and .Values.secureProfile (not .Values.config.presenterBundleKey)"
        in helpers
    )
    refusals = (CHART / "ci" / "check-refusals.sh").read_text()
    assert "expect_refusal secure-without-presenters" in refusals
    defaults = yaml.safe_load((CHART / "values.yaml").read_text())
    for values_file in sorted((CHART / "ci").glob("*-values.yaml")):
        values = yaml.safe_load(values_file.read_text())
        if not values.get("secureProfile", defaults["secureProfile"]):
            continue
        key = values.get("config", {}).get("presenterBundleKey")
        assert key, f"{values_file.name} runs the secure profile without presenters"
    postgres = yaml.safe_load((CHART / "ci" / "postgres-values.yaml").read_text())
    key = postgres["config"]["presenterBundleKey"]
    e2e = (CHART / "ci" / "kind-e2e.sh").read_text()
    assert f"--from-file={key}=" in e2e
