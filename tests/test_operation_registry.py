"""A capability covers only the operations the operator declared (ADR 0025).

External review, 19 October 2026, finding 1: an agent granted only
``crm.read_contact`` obtained a permit for ``POST /api/v1/transfers`` on a
payment service and the receiver admitted it. The review's probe is
inverted here, with its acceptance list.

Claims -> tests:
  - A request its capability does not declare is a sealed BLOCK, decided
    before the ladder: write method, other service, other account, undeclared
    route, wrong parameters, relabelled action
    -> test_undeclared_request_is_a_sealed_block[*]
  - The review's probe: read grant, transfer request -> no permit, nothing
    for the receiver -> test_read_grant_cannot_obtain_a_transfer_permit
  - Mint re-checks: a credential audience the capability does not declare,
    or a registry that no longer declares the operation, refuses
    -> test_mint_checks_the_credential_audience,
       test_mint_rechecks_the_current_registry
  - Under the secure profile a mint without a registry is refused, and the
    profile starts with an empty one -> test_secure_profile_*
  - A blocked request spends no grant budget
    -> test_blocked_request_spends_no_budget
  - Malformed registries stop start-up -> test_malformed_registry_is_refused[*]
Legitimate control: a declared request is allowed, minted with the operation
id and registry digest, and admitted by the receiver.
"""

from __future__ import annotations

import importlib
import json
from datetime import UTC, datetime

import pytest
from nacl.signing import SigningKey

from agent_dna.authority_v01 import sha256_digest
from agent_dna.operation_registry import (
    OPERATION_MISMATCH,
    OPERATION_NOT_DECLARED,
    OperationRegistryError,
    parse_operation_registry,
)
from agent_dna.receiver.gate import ReceiverGate
from agent_dna.receiver.ledger import ReceiverLedger
from agent_dna.receiver.permit_header import PERMIT_HEADER, encode_permit_header
from tests.decide_binding import decide_json, dispatch_context_for, execution_action_for
from tests.test_authorize_mint_claim import (
    AGENT,
    ARGS,
    ORG,
    WIRE,
    _authorize_body,
    _dispatch,
    build_mint_env,
)

READ_CONTACT = {
    "operation_id": "crm-read-contact-v1",
    "capability": "crm.read_contact",
    "transport": "https",
    "destination": "crm.store.example",
    "operation": "GET /v1/contacts",
    "resource_prefix": "crm:",
    "parameters_schema": {
        "type": "object",
        "properties": {"note": {"type": "string"}},
        "required": ["note"],
        "additionalProperties": False,
    },
}


def _registry(*operations):
    return {"spec": "pv-operations/0.1", "operations": list(operations)}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    path = tmp_path / "operations.json"
    path.write_text(json.dumps(_registry(READ_CONTACT)), encoding="utf-8")
    monkeypatch.setenv("PV_OPERATIONS_FILE", str(path))
    yield from build_mint_env(tmp_path, monkeypatch)


def _decide(
    env,
    *,
    capability="crm.read_contact",
    action=None,
    arguments=None,
    resource="crm:contact",
    **dispatch,
):
    ctx = dict(
        adapter="https",
        transport="https",
        operation="GET /v1/contacts",
        destination="crm.store.example",
        wire_content_type="application/json",
    )
    ctx.update(dispatch)
    body = decide_json(
        AGENT,
        capability,
        arguments=dict(ARGS if arguments is None else arguments),
        resource=resource,
        org=ORG,
        dispatch_context=dispatch_context_for(**ctx),
    )
    if action is not None:
        body["execution_action"]["action"] = action
    return env["client"].post(
        "/v1/decide", headers={"X-API-Key": env["key"]}, json=body
    )


# ---- the declared request: the legitimate control ---------------------------------


def test_declared_request_is_allowed_minted_and_admitted(env, tmp_path):
    decided = _decide(env)
    assert decided.status_code == 200, decided.text
    minted = env["client"].post(
        "/v1/authorize",
        headers={"X-API-Key": env["key"]},
        json=_authorize_body(decided.json()["record"]),
    )
    assert minted.status_code == 200, minted.text
    registry = env["server"].state["operation_registry"]
    assert minted.json()["operation"] == {
        "operation_id": "crm-read-contact-v1",
        "registry_digest": registry.digest,
    }
    gate = ReceiverGate(
        receiver_id="crm.store.example",
        destinations=frozenset({"crm.store.example"}),
        trust_bundle=json.loads(env["bundle_path"].read_text()),
        ledger=ReceiverLedger(tmp_path / "receiver.db"),
        receipt_signing_key=SigningKey.generate(),
        receipt_key_id="independent-receiver",
    )
    admitted = gate.check(
        method="GET",
        path="/v1/contacts",
        headers={
            PERMIT_HEADER: encode_permit_header(minted.json()["authorization"]),
            "Content-Type": "application/json",
        },
        body=WIRE,
        received_at=datetime.now(UTC),
    )
    assert admitted.admitted, admitted
    runtime = env["client"].get("/v1/runtime", headers={"X-API-Key": env["key"]}).json()
    assert runtime["composition"]["operation_registry"]["status"] == "attached"
    assert registry.digest in runtime["composition"]["operation_registry"]["detail"]


# ---- what a read capability must not reach ----------------------------------------


@pytest.mark.parametrize(
    "overrides, expected",
    [
        ({"operation": "POST /v1/contacts"}, OPERATION_MISMATCH),
        (
            {
                "destination": "payments.partner.example",
                "operation": "POST /api/v1/transfers",
            },
            OPERATION_MISMATCH,
        ),
        ({"resource": "billing:account-9"}, OPERATION_MISMATCH),
        ({"operation": "GET /v1/contacts/export"}, OPERATION_MISMATCH),
        ({"arguments": {"note": 5}}, OPERATION_MISMATCH),
        ({"arguments": {"note": "x", "amount": 18000}}, OPERATION_MISMATCH),
        ({"capability": "crm.export_all"}, OPERATION_NOT_DECLARED),
    ],
    ids=[
        "write-method",
        "other-service",
        "other-account",
        "undeclared-route",
        "wrong-parameter-type",
        "extra-parameter",
        "undeclared-capability",
    ],
)
def test_undeclared_request_is_a_sealed_block(env, overrides, expected):
    decided = _decide(env, **overrides)
    assert decided.status_code == 403, decided.text
    body = decided.json()
    assert body["triggered_by"] == "operation_registry"
    assert body["reason"].startswith(expected)
    record = body["record"]
    assert record["decision"] == "block"
    stored = env["server"].state["store"].get_decision(record["decision_id"])
    assert stored is not None and stored["decision"] == "block"  # sealed evidence
    refused = env["client"].post(
        "/v1/authorize", headers={"X-API-Key": env["key"]}, json=_authorize_body(record)
    )
    assert refused.status_code in (403, 404)
    assert "authorization" not in refused.json()


def test_relabelled_action_is_refused_by_the_existing_binding(env):
    """The execution action must already name its capability (decide binding)."""
    decided = _decide(env, action="payments.pay_invoice")
    assert decided.status_code == 422
    assert "must match capability" in decided.text


def test_read_grant_cannot_obtain_a_transfer_permit(env):
    """The review's probe 5, through the public API with a valid key."""
    decided = _decide(
        env, destination="payments.partner.example", operation="POST /api/v1/transfers"
    )
    assert decided.status_code == 403
    assert decided.json()["triggered_by"] == "operation_registry"
    transfer = _dispatch(
        destination="payments.partner.example",
        operation="POST /api/v1/transfers",
        credential_audience="payments.partner.example",
    )
    refused = env["client"].post(
        "/v1/authorize",
        headers={"X-API-Key": env["key"]},
        json=_authorize_body(decided.json()["record"], dispatch=transfer),
    )
    assert refused.status_code in (403, 404)
    assert "authorization" not in refused.json()


# ---- mint re-checks ----------------------------------------------------------------


def test_mint_checks_the_credential_audience(env):
    """The decide-time context carries no credential audience; mint checks it."""
    record = _decide(env).json()["record"]
    body = _authorize_body(
        record, dispatch=_dispatch(credential_audience="payments.partner.example")
    )
    refused = env["client"].post(
        "/v1/authorize", headers={"X-API-Key": env["key"]}, json=body
    )
    assert refused.status_code == 403, refused.text
    assert refused.json()["detail"]["reason_code"] == "AUTHORIZE_OPERATION_MISMATCH"
    assert "credential_audience" in refused.json()["detail"]["detail"]


def test_mint_rechecks_the_current_registry(env):
    record = _decide(env).json()["record"]
    env["server"].state["operation_registry"] = parse_operation_registry(_registry())
    refused = env["client"].post(
        "/v1/authorize", headers={"X-API-Key": env["key"]}, json=_authorize_body(record)
    )
    assert refused.status_code == 403
    assert refused.json()["detail"]["reason_code"] == "AUTHORIZE_OPERATION_NOT_DECLARED"


# ---- the secure profile -------------------------------------------------------------

PAY = {
    "operation_id": "pay-invoice-v1",
    "capability": "payments.pay_invoice",
    "transport": "https",
    "destination": "payments.partner.example",
    "operation": "POST /api/v1/transfers",
    "resource_prefix": "vendor:",
    "parameters_schema": {"type": "object", "required": ["amount"]},
}


def _secure(tmp_path, monkeypatch, *, operations):
    from tests.test_init_secure_profile import _load_env
    from tools.init_secure_profile import provision

    out = tmp_path / "secure"
    provision(
        out,
        org=ORG,
        agents=[AGENT],
        grants=[{"agent_id": AGENT, "capability": "payments.pay_invoice"}],
        operations=operations,
    )
    rows = json.loads((out / "grants.json").read_text())
    for row in rows:
        if row["agent_id"] == AGENT:
            row["budget"] = 5000
    (out / "grants.json").write_text(json.dumps(rows))
    env_vars = _load_env(out / "secure.env", monkeypatch)
    # a known capability, so the plain ALLOW path runs without drift review
    monkeypatch.setenv("PV_BASELINE_CAPABILITIES", "payments.pay_invoice")
    import api.server as server

    importlib.reload(server)
    server._pv_signer_cache.clear()
    return server, env_vars["PV_KEY_TREASURY_AGENT"], out


def _pay(client, key, amount, **dispatch):
    ctx = dict(
        adapter="https",
        transport="https",
        operation="POST /api/v1/transfers",
        destination="payments.partner.example",
        wire_content_type="application/json",
    )
    ctx.update(dispatch)
    body = decide_json(
        AGENT,
        "payments.pay_invoice",
        arguments={"amount": amount},
        resource="vendor:V-100",
        org=ORG,
        dispatch_context=dispatch_context_for(**ctx),
        execution_id=f"flow-{amount}-{len(dispatch)}",
    )
    return client.post("/v1/decide", headers={"X-API-Key": key}, json=body)


def test_secure_profile_starts_with_an_empty_registry(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    server, key, out = _secure(tmp_path, monkeypatch, operations=None)
    assert json.loads((out / "operations.json").read_text())["operations"] == []
    with TestClient(server.app) as client:
        blocked = _pay(client, key, 100)
        assert blocked.status_code == 403
        assert blocked.json()["reason"].startswith(OPERATION_NOT_DECLARED)


def test_secure_profile_refuses_to_mint_without_a_registry(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    server, key, _out = _secure(tmp_path, monkeypatch, operations=[PAY])
    monkeypatch.delenv("PV_OPERATIONS_FILE")
    importlib.reload(server)
    server._pv_signer_cache.clear()
    with TestClient(server.app) as client:
        manifest = client.get("/v1/runtime", headers={"X-API-Key": key}).json()
        assert (
            "every mint is refused"
            in manifest["composition"]["operation_registry"]["detail"]
        )
        decided = _pay(client, key, 100)
        assert decided.status_code == 200, decided.text
        record = decided.json()["record"]
        action = execution_action_for(
            AGENT,
            "payments.pay_invoice",
            {"amount": 100},
            resource="vendor:V-100",
            org=ORG,
        )
        body = _authorize_body(
            record,
            wire=b'{"amount":100}',
            dispatch=_dispatch(
                destination="payments.partner.example",
                operation="POST /api/v1/transfers",
                credential_audience="payments.partner.example",
            ),
            action=action,
        )
        body["security_events"] = [
            {
                "spec": "pv-agent-security-event/1.0",
                "event_id": "registry-required-event",
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
        refused = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
        assert refused.status_code == 403, refused.text
        assert (
            refused.json()["detail"]["reason_code"] == "AUTHORIZE_OPERATIONS_REQUIRED"
        )


def test_blocked_request_spends_no_budget(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    server, key, _out = _secure(tmp_path, monkeypatch, operations=[PAY])
    with TestClient(server.app) as client:
        blocked = _pay(client, key, 4000, operation="POST /api/v1/transfers/bulk")
        assert blocked.status_code == 403
        assert blocked.json()["triggered_by"] == "operation_registry"
        allowed = _pay(client, key, 4000)
        # had the blocked request spent its 4000, this one would exceed 5000
        assert allowed.status_code == 200, allowed.text


# ---- parsing --------------------------------------------------------------------------


def _without(key):
    return {k: v for k, v in READ_CONTACT.items() if k != key}


@pytest.mark.parametrize(
    "document, message",
    [
        ({"spec": "other", "operations": []}, "spec"),
        ({"spec": "pv-operations/0.1", "operations": {}}, "list"),
        (_registry(_without("parameters_schema")), "parameters_schema is required"),
        (_registry(_without("destination")), "destination"),
        (_registry({**READ_CONTACT, "operation": "get contacts"}), "METHOD /path"),
        (_registry({**READ_CONTACT, "methods": ["GET"]}), "unknown fields"),
        (_registry({**READ_CONTACT, "resources": ["crm:a"]}), "not both"),
        (
            _registry({**READ_CONTACT, "parameters_schema": {"type": "nope"}}),
            "parameters_schema",
        ),
        (_registry(READ_CONTACT, READ_CONTACT), "duplicate operation_id"),
    ],
    ids=[
        "spec",
        "not-a-list",
        "no-schema",
        "no-destination",
        "bad-operation",
        "unknown-field",
        "both-resource-forms",
        "bad-schema",
        "duplicate-id",
    ],
)
def test_malformed_registry_is_refused(document, message):
    with pytest.raises(OperationRegistryError, match=message):
        parse_operation_registry(document)


def test_a_bad_registry_file_stops_startup(tmp_path):
    from api.server import _operation_registry

    path = tmp_path / "operations.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(RuntimeError, match="PV_OPERATIONS_FILE"):
        _operation_registry({"PV_OPERATIONS_FILE": str(path)})
    assert _operation_registry({}) is None


def test_provision_refuses_a_bad_declaration(tmp_path):
    from tools.init_secure_profile import provision

    with pytest.raises(OperationRegistryError):
        provision(
            tmp_path / "p",
            org=ORG,
            agents=[AGENT],
            grants=[],
            operations=[_without("parameters_schema")],
        )


def test_digest_tracks_the_content():
    one = parse_operation_registry(_registry(READ_CONTACT))
    same = parse_operation_registry(json.loads(json.dumps(_registry(READ_CONTACT))))
    other = parse_operation_registry(
        _registry({**READ_CONTACT, "destination": "x.example"})
    )
    assert one.digest == same.digest != other.digest
