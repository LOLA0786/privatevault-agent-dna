"""PV-001 adversarial: every bound-field mutation refuses mint; no permit issued."""

from __future__ import annotations

import copy
import importlib
import json
import time

import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from agent_dna.apikeys import generate_key
from agent_dna.authority_v01 import (
    CANONICALIZATION,
    TRUST_SPEC,
    encode_public_key,
)
from agent_dna.authorize_binding import (
    AUTHORIZE_ACTION_DIGEST_MISMATCH,
    AUTHORIZE_ACTION_DIGEST_REQUIRED,
    AUTHORIZE_DISPATCH_CONTEXT_DIGEST_MISMATCH,
    AUTHORIZE_DISPATCH_CONTEXT_DIGEST_REQUIRED,
    AUTHORIZE_PROTOCOL_NOT_AUTHORIZING,
    bind_authorize_to_sealed_allow,
)
from agent_dna.decision import Decision
from agent_dna.decision_record import DRP_V01, DRP_V02, build_record
from agent_dna.execution_v01 import sha256_bytes_digest
from agent_dna.trace import AgentAction

Z = "sha256:" + ("0" * 64)
ONE = "sha256:" + ("1" * 64)
WIRE = b'{"account":"4471","amount":400000,"currency":"INR"}'
PEER = b"tls-spki:payments.store.example:v3"
ORG = "org-demo"
AGENT = "treasury-agent"
ARGS = {"note": "pv001"}
CAP = "crm.read_contact"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    op = generate_key(AGENT, "full")
    keys_path = tmp_path / "keys.json"
    keys_path.write_text(
        json.dumps({op["hash"]: {"name": op["name"], "scope": "full"}}),
        encoding="utf-8",
    )
    sk = SigningKey.generate()
    key_path = tmp_path / "exec.key"
    key_path.write_bytes(bytes(sk))
    bundle = {
        "spec": TRUST_SPEC,
        "canonicalization": CANONICALIZATION,
        "organisation_id": ORG,
        "bundle_version": 1,
        "pinned_at": "2026-07-31T11:00:00Z",
        "keys": [
            {
                "key_id": "k1",
                "principal": f"execution-runtime@{ORG}",
                "algorithm": "ed25519",
                "public_key": encode_public_key(sk),
                "usages": ["execution_authorization_signer"],
            }
        ],
    }
    bundle_path = tmp_path / "trust.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "pv.db"))
    monkeypatch.setenv("PV_API_KEYS_FILE", str(keys_path))
    monkeypatch.setenv("PV_EXECUTION_SIGNER_KEY", str(key_path))
    monkeypatch.setenv("PV_TRUST_BUNDLE", str(bundle_path))
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)

    import api.server as server

    server._pv_signer_cache.clear()
    importlib.reload(server)
    server._pv_signer_cache.clear()
    with TestClient(server.app) as client:
        # Authorization defaults to deny-all (F-05). These tests exercise
        # the DRP 0.2 binding, not the grant layer, so grant the capability
        # explicitly rather than relying on an unconfigured authorizer.
        from agent_dna.grants import GrantRegistry

        reg = GrantRegistry()
        reg.authorization_mode = "grants_file"
        reg.grant(agent_id=AGENT, capability=CAP, granted_by="test-fixture")
        server.state["engine"].authorizer = reg
        yield {"client": client, "key": op["key"], "server": server}


def _execution_action(**overrides):
    base = {
        "subject_principal": f"{AGENT}@{ORG}",
        "subject_key_id": AGENT,
        "action": CAP,
        "resource": "crm:contact",
        "parameters": dict(ARGS),
    }
    base.update(overrides)
    return base


def _dispatch_context(**overrides):
    base = {
        "adapter": "https",
        "transport": "https",
        "operation": "GET /v1/contacts",
        "destination": "crm.store.example",
        "wire_content_type": "application/json",
    }
    base.update(overrides)
    return base


def _ea_dispatch(**overrides):
    """Full EA dispatch object (schema-closed). Adapter defaults from transport."""
    ctx = _dispatch_context()
    base = {
        "transport": ctx["transport"],
        "destination": ctx["destination"],
        "operation": ctx["operation"],
        "wire_content_type": ctx["wire_content_type"],
        "wire_content_encoding": "identity",
        "tool_id": "crm.read_contact.v1",
        "tool_schema_digest": Z,
        "tool_artifact_digest": ONE,
        "credential_audience": ctx["destination"],
        "idempotency_key_digest": Z,
        "retry_policy_digest": ONE,
    }
    # adapter is not an EA field; handled only via decide dispatch_context
    # or via transport default at authorize projection time.
    overrides = {k: v for k, v in overrides.items() if k != "adapter"}
    base.update(overrides)
    return base


def _decide(client, key):
    r = client.post(
        "/v1/decide",
        headers={"X-API-Key": key},
        json={
            "agent_id": AGENT,
            "capability": CAP,
            "timestamp": time.time(),
            "arguments": dict(ARGS),
            "execution_action": _execution_action(),
            "dispatch_context": _dispatch_context(),
        },
    )
    assert r.status_code == 200, r.text
    record = r.json()["record"]
    assert record["protocol_version"] == DRP_V02
    assert record["action_digest"]
    assert record["dispatch_context_digest"]
    return record


def _authorize(client, key, record, *, action=None, dispatch=None):
    body = {
        "request_id": "req-pv001",
        "agent_id": AGENT,
        "organisation_id": ORG,
        "decision_id": record["decision_id"],
        "action": action if action is not None else _execution_action(),
        "dispatch": dispatch if dispatch is not None else _ea_dispatch(),
        "expected_wire_bytes_digest": sha256_bytes_digest(WIRE),
        "expected_wire_bytes_length": len(WIRE),
        "expected_peer_identity_digest": sha256_bytes_digest(PEER),
        "decision_receipt_digest": "sha256:" + record["record_hash"],
        "authority_receipt_digest": ONE,
        "state_snapshot_digest": Z,
        "policy_bundle_digest": ONE,
        "obligations_digest": Z,
    }
    return client.post(
        "/v1/authorize",
        headers={"X-API-Key": key},
        json=body,
    )


def _assert_no_permit(response):
    assert response.status_code in (403, 404, 422), response.text
    body = response.json()
    detail = body.get("detail")
    if isinstance(detail, dict):
        assert "authorization" not in detail
        assert detail.get("reason_code")
    assert "execution_authorization_id" not in json.dumps(body)


def test_happy_path_mints_from_drp02(env):
    client, key = env["client"], env["key"]
    record = _decide(client, key)
    r = _authorize(client, key, record)
    assert r.status_code == 200, r.text
    assert r.json()["authorization"]["execution_authorization_id"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("subject_principal", "attacker@evil.example"),
        ("subject_key_id", "other-agent"),
        ("action", "crm.delete_contact"),
        ("parameters", {"note": "mutated"}),
        ("resource", "crm:secret"),
    ],
)
def test_action_field_mutation_refuses_mint(env, field, value):
    client, key = env["client"], env["key"]
    record = _decide(client, key)
    action = _execution_action(**{field: value})
    # Keep capability/arguments aligned for capability mismatch vs digest path.
    if field == "action":
        # capability on record stays CAP; action mismatch triggers ACTION_MISMATCH
        # or DIGEST mismatch depending on order — either refuses mint.
        pass
    r = _authorize(client, key, record, action=action)
    _assert_no_permit(r)
    assert r.json()["detail"]["reason_code"] in {
        AUTHORIZE_ACTION_DIGEST_MISMATCH,
        "AUTHORIZE_ACTION_MISMATCH",
        "AUTHORIZE_ARGUMENTS_DIGEST_MISMATCH",
        "AUTHORIZE_AGENT_MISMATCH",
    }


@pytest.mark.parametrize(
    "field,value",
    [
        ("transport", "stdio"),
        ("operation", "DELETE /v1/contacts"),
        ("destination", "evil.example"),
        ("wire_content_type", "text/plain"),
    ],
)
def test_dispatch_context_field_mutation_refuses_mint(env, field, value):
    client, key = env["client"], env["key"]
    record = _decide(client, key)
    dispatch = _ea_dispatch(**{field: value})
    r = _authorize(client, key, record, dispatch=dispatch)
    _assert_no_permit(r)
    assert (
        r.json()["detail"]["reason_code"] == AUTHORIZE_DISPATCH_CONTEXT_DIGEST_MISMATCH
    )


def test_adapter_mutation_via_decide_context_refuses_mint(env):
    """Adapter is sealed at decide; changing transport (adapter default) refuses."""
    client, key = env["client"], env["key"]
    # Decide with adapter=https, transport=https.
    record = _decide(client, key)
    # Authorize with different transport → projected adapter differs.
    r = _authorize(client, key, record, dispatch=_ea_dispatch(transport="mcp"))
    _assert_no_permit(r)
    assert (
        r.json()["detail"]["reason_code"] == AUTHORIZE_DISPATCH_CONTEXT_DIGEST_MISMATCH
    )


def test_missing_action_digest_on_record_refuses_mint(env):
    client, key = env["client"], env["key"]
    record = _decide(client, key)
    store = env["server"].state["store"]
    # Force a corrupted store view: strip digest then attempt bind via API
    # by substituting a DRP 0.1 ALLOW with same id is hard; call binder directly.
    stripped = copy.deepcopy(record)
    stripped.pop("action_digest", None)
    stripped["protocol_version"] = DRP_V02
    stripped["dispatch_context_digest"] = record["dispatch_context_digest"]
    reason = bind_authorize_to_sealed_allow(
        stripped,
        agent_id=AGENT,
        decision_receipt_digest="sha256:" + record["record_hash"],
        action=_execution_action(),
        dispatch=_ea_dispatch(),
    )
    assert reason == AUTHORIZE_ACTION_DIGEST_REQUIRED
    # Ensure live mint still only for intact record.
    r = _authorize(client, key, record)
    assert r.status_code == 200
    assert store is not None


def test_missing_dispatch_context_digest_on_record_refuses_mint(env):
    record = _decide(env["client"], env["key"])
    stripped = copy.deepcopy(record)
    stripped.pop("dispatch_context_digest", None)
    stripped["protocol_version"] = DRP_V02
    stripped["action_digest"] = record["action_digest"]
    reason = bind_authorize_to_sealed_allow(
        stripped,
        agent_id=AGENT,
        decision_receipt_digest="sha256:" + record["record_hash"],
        action=_execution_action(),
        dispatch=_ea_dispatch(),
    )
    assert reason == AUTHORIZE_DISPATCH_CONTEXT_DIGEST_REQUIRED


def test_drp01_record_cannot_mint(env):
    client, key = env["client"], env["key"]
    server = env["server"]
    # Insert a sealed DRP 0.1 ALLOW directly into the store.
    from agent_dna.advisory import AdvisorySignal, Severity
    from agent_dna.decision import DecisionEngine

    class _S:
        def score(self, action, prev_capability=None):
            return AdvisorySignal(
                agent_id=action.agent_id,
                capability=action.capability,
                drift_score=0.0,
                severity=Severity.INFO,
                reasons=[],
            )

    action = AgentAction(
        agent_id=AGENT,
        capability=CAP,
        timestamp=time.time(),
        arguments=dict(ARGS),
    )
    # An unconfigured authorizer fails closed (F-05), so supply one
    # explicitly. This test is about protocol version refusal at mint,
    # not the grant layer.
    from agent_dna.grants import GrantRegistry

    reg = GrantRegistry()
    reg.authorization_mode = "grants_file"
    reg.grant(agent_id=AGENT, capability=CAP, granted_by="test-fixture")
    result = DecisionEngine(scorer=_S(), authorizer=reg).decide(action)
    assert result.decision == Decision.ALLOW
    rec = build_record(action, result)
    assert rec.protocol_version == DRP_V01
    server.state["store"].append(rec)

    r = _authorize(
        client,
        key,
        {
            "decision_id": rec.decision_id,
            "record_hash": rec.record_hash,
        },
    )
    _assert_no_permit(r)
    assert r.json()["detail"]["reason_code"] == AUTHORIZE_PROTOCOL_NOT_AUTHORIZING


def test_record_substitution_refuses_mint(env):
    client, key = env["client"], env["key"]
    a = _decide(client, key)
    b = _decide(client, key)
    # Use A's id with B's receipt digest.
    r = client.post(
        "/v1/authorize",
        headers={"X-API-Key": key},
        json={
            "request_id": "req-sub",
            "agent_id": AGENT,
            "organisation_id": ORG,
            "decision_id": a["decision_id"],
            "action": _execution_action(),
            "dispatch": _ea_dispatch(),
            "expected_wire_bytes_digest": sha256_bytes_digest(WIRE),
            "expected_wire_bytes_length": len(WIRE),
            "expected_peer_identity_digest": sha256_bytes_digest(PEER),
            "decision_receipt_digest": "sha256:" + b["record_hash"],
            "authority_receipt_digest": ONE,
            "state_snapshot_digest": Z,
            "policy_bundle_digest": ONE,
            "obligations_digest": Z,
        },
    )
    _assert_no_permit(r)
    assert r.json()["detail"]["reason_code"] == "AUTHORIZE_RECEIPT_DIGEST_MISMATCH"


def test_caller_supplied_digest_on_decide_refused(env):
    client, key = env["client"], env["key"]
    r = client.post(
        "/v1/decide",
        headers={"X-API-Key": key},
        json={
            "agent_id": AGENT,
            "capability": CAP,
            "timestamp": time.time(),
            "arguments": dict(ARGS),
            "execution_action": {
                **_execution_action(),
                "action_digest": Z,
            },
            "dispatch_context": _dispatch_context(),
        },
    )
    assert r.status_code == 422
