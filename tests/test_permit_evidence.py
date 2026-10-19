"""The evidence a permit cites is the server's, not the caller's (ADR 0026).

External review, 19 October 2026, finding 3: ``/v1/authorize`` copied the
caller's policy, state-snapshot, authority-receipt and obligations digests
into the signed permit, so the signature proved nothing about what had been
checked. The review's probe (arbitrary digests in, the same digests signed)
is inverted here.

Claims -> tests:
  - Decide seals the four references the server can stand behind: its
    policy bundle, the grant the engine used, and the all-zero digest for
    state and obligations it did not evaluate
    -> test_decide_seals_the_permit_evidence
  - Server mode: the permit carries the sealed values; a caller value that
    differs is refused, repeating them is fine
    -> test_server_mode_permit_cites_the_sealed_evidence,
       test_server_mode_refuses_caller_evidence[*]
  - A changed grants or operations file between decide and mint refuses
    the mint; the same configuration after a restart mints
    -> test_server_mode_refuses_after_a_configuration_change[*],
       test_server_mode_mints_after_a_restart_with_the_same_configuration
  - A decision with no sealed evidence cannot mint in server mode
    -> test_server_mode_refuses_a_record_without_sealed_evidence
  - Caller mode (legacy, off-profile default): caller values are signed and
    listed as caller assertions; omitted ones are the sealed values
    -> test_caller_mode_*
  - Secure profile: server mode by default, caller mode refused at start-up,
    and the review's probe is refused
    -> test_secure_profile_*
"""

from __future__ import annotations

import importlib
import json
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from agent_dna.authority_v01 import sha256_digest
from agent_dna.control_posture import posture_from_evidence
from agent_dna.permit_evidence import (
    CALLER,
    FIELDS,
    NONE_DIGEST,
    SERVER,
    PermitEvidenceError,
    evidence_mode,
    grant_digest,
    policy_bundle_digest,
    sealed_evidence,
)
from agent_dna.receiver.gate import ReceiverGate
from agent_dna.receiver.ledger import ReceiverLedger
from agent_dna.receiver.permit_header import PERMIT_HEADER, encode_permit_header
from tests.decide_binding import execution_action_for
from tests.test_authorize_mint_claim import (
    AGENT,
    ORG,
    WIRE,
    _authorize_body,
    _dispatch,
    build_mint_env,
)
from tests.test_init_secure_profile import presenter_digest
from tests.test_operation_registry import (
    PAY,
    READ_CONTACT,
    _decide,
    _pay,
    _registry,
    _secure,
)

ONE = "sha256:" + "1" * 64


def _env(tmp_path, monkeypatch, mode):
    path = tmp_path / "operations.json"
    path.write_text(json.dumps(_registry(READ_CONTACT)), encoding="utf-8")
    monkeypatch.setenv("PV_OPERATIONS_FILE", str(path))
    if mode is None:
        monkeypatch.delenv("PV_PERMIT_EVIDENCE", raising=False)
    else:
        monkeypatch.setenv("PV_PERMIT_EVIDENCE", mode)
    return build_mint_env(tmp_path, monkeypatch)


@pytest.fixture()
def server_env(tmp_path, monkeypatch):
    yield from _env(tmp_path, monkeypatch, SERVER)


@pytest.fixture()
def caller_env(tmp_path, monkeypatch):
    yield from _env(tmp_path, monkeypatch, None)


def _without_evidence(body):
    return {k: v for k, v in body.items() if k not in FIELDS}


def _mint(env, body):
    return env["client"].post(
        "/v1/authorize", headers={"X-API-Key": env["key"]}, json=body
    )


def _allow(env):
    decided = _decide(env)
    assert decided.status_code == 200, decided.text
    return decided.json()["record"]


# ---- what decide seals --------------------------------------------------------------


def test_decide_seals_the_permit_evidence(server_env):
    record = _allow(server_env)
    sealed = sealed_evidence(record)
    server = server_env["server"]
    registry = server.state["engine"].authorizer
    (grant_id,) = list(registry._grants)
    assert sealed == {
        "policy_bundle_digest": server.state["permit_evidence"]["policy_bundle_digest"],
        "authority_receipt_digest": grant_digest(registry.snapshot_of(grant_id)),
        "state_snapshot_digest": NONE_DIGEST,
        "obligations_digest": NONE_DIGEST,
    }
    runtime = (
        server_env["client"]
        .get("/v1/runtime", headers={"X-API-Key": server_env["key"]})
        .json()["composition"]["permit_evidence"]
    )
    assert runtime["status"] == "attached" and runtime["mode"] == SERVER
    assert runtime["policy_bundle_digest"] == sealed["policy_bundle_digest"]


def test_a_caller_cannot_plant_permit_evidence_at_decide(server_env):
    from tests.decide_binding import decide_json, dispatch_context_for

    body = decide_json(
        AGENT,
        "crm.read_contact",
        arguments={"note": "x"},
        resource="crm:contact",
        org=ORG,
        dispatch_context=dispatch_context_for(
            adapter="https",
            transport="https",
            operation="GET /v1/contacts",
            destination="crm.store.example",
            wire_content_type="application/json",
        ),
    )
    body["evidence"] = {
        "enforcement_control_posture": json.dumps(
            {"permit_evidence": dict.fromkeys(FIELDS, ONE)}
        ),
        "permit_evidence": dict.fromkeys(FIELDS, ONE),
    }
    decided = server_env["client"].post(
        "/v1/decide", headers={"X-API-Key": server_env["key"]}, json=body
    )
    assert decided.status_code == 200, decided.text
    sealed = sealed_evidence(decided.json()["record"])
    assert sealed is not None and ONE not in sealed.values()


# ---- server mode --------------------------------------------------------------------


def test_server_mode_permit_cites_the_sealed_evidence(server_env, tmp_path):
    record = _allow(server_env)
    sealed = sealed_evidence(record)
    minted = _mint(server_env, _without_evidence(_authorize_body(record)))
    assert minted.status_code == 200, minted.text
    permit = minted.json()["authorization"]
    assert {name: permit[name] for name in FIELDS} == sealed
    assert minted.json()["evidence"] == {
        "mode": SERVER,
        **sealed,
        "caller_asserted": [],
    }
    gate = ReceiverGate(
        receiver_id="crm.store.example",
        destinations=frozenset({"crm.store.example"}),
        trust_bundle=json.loads(server_env["bundle_path"].read_text()),
        ledger=ReceiverLedger(tmp_path / "receiver.db"),
        receipt_signing_key=SigningKey.generate(),
        receipt_key_id="independent-receiver",
    )
    admitted = gate.check(
        method="GET",
        path="/v1/contacts",
        headers={
            PERMIT_HEADER: encode_permit_header(permit),
            "Content-Type": "application/json",
        },
        body=WIRE,
        received_at=datetime.now(UTC),
    )
    assert admitted.admitted, admitted


def test_server_mode_accepts_the_sealed_values_repeated(server_env):
    record = _allow(server_env)
    body = {**_without_evidence(_authorize_body(record)), **sealed_evidence(record)}
    minted = _mint(server_env, body)
    assert minted.status_code == 200, minted.text


@pytest.mark.parametrize("field", FIELDS)
def test_server_mode_refuses_caller_evidence(server_env, field):
    record = _allow(server_env)
    body = _without_evidence(_authorize_body(record))
    body[field] = ONE
    refused = _mint(server_env, body)
    assert refused.status_code == 403, refused.text
    detail = refused.json()["detail"]
    assert detail["reason_code"] == "AUTHORIZE_EVIDENCE_MISMATCH"
    assert field in detail["detail"]
    # nothing was minted: the honest request still gets the decision's permit
    honest = _mint(server_env, _without_evidence(_authorize_body(record)))
    assert honest.status_code == 200, honest.text


@pytest.mark.parametrize("changed", ["grants", "operations"])
def test_server_mode_refuses_after_a_configuration_change(
    tmp_path, monkeypatch, changed
):
    lifecycle = _env(tmp_path, monkeypatch, SERVER)
    env = next(lifecycle)
    record = _allow(env)
    lifecycle.close()  # the deciding server stops
    if changed == "grants":
        rows = json.loads(env["grants_path"].read_text())
        rows[0]["budget"] = 10
        env["grants_path"].write_text(json.dumps(rows), encoding="utf-8")
    else:
        (tmp_path / "operations.json").write_text(
            json.dumps(_registry(READ_CONTACT, PAY)), encoding="utf-8"
        )
    server = env["server"]
    importlib.reload(server)
    server._pv_signer_cache.clear()
    with TestClient(server.app) as client:  # same database, new configuration
        refused = client.post(
            "/v1/authorize",
            headers={"X-API-Key": env["key"]},
            json=_without_evidence(_authorize_body(record)),
        )
    assert refused.status_code == 403, refused.text
    assert refused.json()["detail"]["reason_code"] == "AUTHORIZE_POLICY_CHANGED"


def test_server_mode_mints_after_a_restart_with_the_same_configuration(
    tmp_path, monkeypatch
):
    lifecycle = _env(tmp_path, monkeypatch, SERVER)
    env = next(lifecycle)
    record = _allow(env)
    lifecycle.close()
    server = env["server"]
    importlib.reload(server)
    server._pv_signer_cache.clear()
    with TestClient(server.app) as client:
        minted = client.post(
            "/v1/authorize",
            headers={"X-API-Key": env["key"]},
            json=_without_evidence(_authorize_body(record)),
        )
    assert minted.status_code == 200, minted.text


def test_server_mode_refuses_a_record_without_sealed_evidence(server_env, monkeypatch):
    # A record decided before ADR 0026 carries no permit_evidence.
    monkeypatch.setattr(server_env["server"], "PERMIT_EVIDENCE_KEY", "pre_0026")
    record = _allow(server_env)
    assert sealed_evidence(record) is None
    refused = _mint(server_env, _authorize_body(record))
    assert refused.status_code == 403, refused.text
    assert refused.json()["detail"]["reason_code"] == "AUTHORIZE_EVIDENCE_UNKNOWN"


# ---- caller mode (legacy) -----------------------------------------------------------


def test_caller_mode_signs_caller_values_and_says_so(caller_env):
    record = _allow(caller_env)
    sealed = sealed_evidence(record)
    minted = _mint(caller_env, _authorize_body(record))  # ONE / zero placeholders
    assert minted.status_code == 200, minted.text
    permit = minted.json()["authorization"]
    assert permit["policy_bundle_digest"] == ONE
    assert permit["authority_receipt_digest"] == ONE
    evidence = minted.json()["evidence"]
    assert evidence["mode"] == CALLER
    # the zero placeholders equal the sealed "not evaluated" values
    assert evidence["caller_asserted"] == [
        "policy_bundle_digest",
        "authority_receipt_digest",
    ]
    assert sealed["state_snapshot_digest"] == permit["state_snapshot_digest"]
    runtime = (
        caller_env["client"]
        .get("/v1/runtime", headers={"X-API-Key": caller_env["key"]})
        .json()["composition"]["permit_evidence"]
    )
    assert runtime["status"] == "not_configured"
    assert "caller's assertion" in runtime["detail"]


def test_caller_mode_fills_omitted_values_from_the_record(caller_env):
    record = _allow(caller_env)
    minted = _mint(caller_env, _without_evidence(_authorize_body(record)))
    assert minted.status_code == 200, minted.text
    permit = minted.json()["authorization"]
    assert {name: permit[name] for name in FIELDS} == sealed_evidence(record)
    assert minted.json()["evidence"]["caller_asserted"] == []


def test_caller_mode_needs_values_when_nothing_is_sealed(caller_env, monkeypatch):
    monkeypatch.setattr(caller_env["server"], "PERMIT_EVIDENCE_KEY", "pre_0026")
    record = _allow(caller_env)
    refused = _mint(caller_env, _without_evidence(_authorize_body(record)))
    assert refused.status_code == 422, refused.text
    assert refused.json()["detail"]["reason_code"] == "AUTHORIZE_EVIDENCE_REQUIRED"
    minted = _mint(caller_env, _authorize_body(record))
    assert minted.status_code == 200, minted.text
    assert minted.json()["evidence"]["caller_asserted"] == list(FIELDS)


# ---- the secure profile -------------------------------------------------------------


def _secure_mint_body(decided, out, **overrides):
    record = decided.json()["record"]
    action = execution_action_for(
        AGENT, "payments.pay_invoice", {"amount": 100}, resource="vendor:V-100", org=ORG
    )
    body = _without_evidence(
        _authorize_body(
            record,
            wire=b'{"amount":100}',
            dispatch=_dispatch(
                destination="payments.partner.example",
                operation="POST /api/v1/transfers",
                credential_audience="payments.partner.example",
            ),
            action=action,
        )
    )
    body["presenter_identity_digest"] = presenter_digest(out, AGENT)
    body["security_events"] = [
        {
            "spec": "pv-agent-security-event/1.0",
            "event_id": f"evidence-event-{len(overrides)}",
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
    body.update(overrides)
    return body


def test_secure_profile_refuses_the_reviews_probe(tmp_path, monkeypatch):
    monkeypatch.delenv("PV_PERMIT_EVIDENCE", raising=False)
    server, key, out = _secure(tmp_path, monkeypatch, operations=[PAY])
    with TestClient(server.app) as client:
        decided = _pay(client, key, 100)
        assert decided.status_code == 200, decided.text
        sealed = sealed_evidence(decided.json()["record"])
        # The review's probe: arbitrary digests in, expecting them signed.
        probe = _secure_mint_body(
            decided,
            out,
            policy_bundle_digest=ONE,
            authority_receipt_digest=ONE,
            state_snapshot_digest=ONE,
            obligations_digest=ONE,
        )
        refused = client.post("/v1/authorize", headers={"X-API-Key": key}, json=probe)
        assert refused.status_code == 403, refused.text
        assert refused.json()["detail"]["reason_code"] == "AUTHORIZE_EVIDENCE_MISMATCH"
        honest = client.post(
            "/v1/authorize",
            headers={"X-API-Key": key},
            json=_secure_mint_body(decided, out),
        )
        assert honest.status_code == 200, honest.text
        permit = honest.json()["authorization"]
        assert {name: permit[name] for name in FIELDS} == sealed
        assert permit["state_snapshot_digest"] == NONE_DIGEST
        assert honest.json()["evidence"]["mode"] == SERVER


def test_secure_profile_refuses_caller_mode_at_startup(tmp_path, monkeypatch):
    server, _key, _out = _secure(tmp_path, monkeypatch, operations=[PAY])
    monkeypatch.setenv("PV_PERMIT_EVIDENCE", "caller")
    importlib.reload(server)
    with pytest.raises(RuntimeError, match="PV_PERMIT_EVIDENCE=caller"):
        with TestClient(server.app):
            pass


# ---- units ---------------------------------------------------------------------------


def test_evidence_mode():
    assert evidence_mode({}, secure=True) == SERVER
    assert evidence_mode({}, secure=False) == CALLER
    assert evidence_mode({"PV_PERMIT_EVIDENCE": "Server"}, secure=False) == SERVER
    with pytest.raises(PermitEvidenceError, match="one of"):
        evidence_mode({"PV_PERMIT_EVIDENCE": "both"}, secure=False)
    with pytest.raises(PermitEvidenceError, match="refuses"):
        evidence_mode({"PV_PERMIT_EVIDENCE": "caller"}, secure=True)


def test_policy_bundle_digest_follows_every_input(tmp_path):
    policy = tmp_path / "policy.yaml"
    grants = tmp_path / "grants.json"
    policy.write_text("rules: []\n")
    grants.write_text("[]")
    env = {"PV_POLICY_FILE": str(policy), "PV_GRANTS_FILE": str(grants)}
    base = policy_bundle_digest(env, operations_digest=None)
    assert base == policy_bundle_digest(dict(env), operations_digest=None)
    assert base != policy_bundle_digest(env, operations_digest=ONE)
    policy.write_text("rules: [{}]\n")
    assert base != policy_bundle_digest(env, operations_digest=None)
    policy.write_text("rules: []\n")
    grants.write_text("[ ]")
    assert base != policy_bundle_digest(env, operations_digest=None)
    opa = {"PV_OPA_ENDPOINT": "https://opa.internal"}
    assert policy_bundle_digest(opa, operations_digest=None) != policy_bundle_digest(
        {**opa, "PV_OPA_POLICY_PATH": "other/path"}, operations_digest=None
    )
    # the policy file wins over OPA, as in the composition root
    assert policy_bundle_digest(
        {**env, **opa}, operations_digest=None
    ) == policy_bundle_digest(env, operations_digest=None)
    with pytest.raises(PermitEvidenceError, match="PV_GRANTS_FILE"):
        policy_bundle_digest(
            {"PV_GRANTS_FILE": str(tmp_path / "missing.json")}, operations_digest=None
        )


def test_grant_digest_ignores_spend():
    terms = {
        "grant_id": "g1",
        "agent_id": "a",
        "capability": "c",
        "granted_by": "ops",
        "expires_at": None,
        "budget": 100,
    }
    assert grant_digest(None) == NONE_DIGEST
    assert grant_digest(terms) == grant_digest(dict(terms))
    assert grant_digest(terms) != grant_digest({**terms, "budget": 10})


def test_sealed_evidence_reads_only_the_posture_item():
    assert sealed_evidence({"evidence": []}) is None
    good = dict.fromkeys(FIELDS, NONE_DIGEST)
    item = {
        "name": "enforcement_control_posture",
        "summary": json.dumps({"permit_evidence": good}),
    }
    assert sealed_evidence({"evidence": [item]}) == good
    partial = {**item, "summary": json.dumps({"permit_evidence": {"x": 1}})}
    assert sealed_evidence({"evidence": [partial]}) is None
    assert posture_from_evidence([item]) is not None
