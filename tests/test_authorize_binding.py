"""Adversarial binding: /v1/authorize mints only against a sealed ALLOW."""

from __future__ import annotations

import importlib
import json
import time

import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from agent_dna.advisory import Severity
from agent_dna.apikeys import generate_key
from agent_dna.authority_v01 import (
    CANONICALIZATION,
    TRUST_SPEC,
    encode_public_key,
    sha256_digest,
)
from agent_dna.authorize_binding import (
    AUTHORIZE_ACTION_MISMATCH,
    AUTHORIZE_AGENT_MISMATCH,
    AUTHORIZE_DECISION_NOT_ALLOW,
    AUTHORIZE_DECISION_NOT_FOUND,
    AUTHORIZE_DECISION_REQUIRED,
    AUTHORIZE_RECEIPT_DIGEST_MISMATCH,
)
from agent_dna.decision import Decision, DecisionResult
from agent_dna.decision_record import build_record
from agent_dna.execution_v01 import (
    sha256_bytes_digest,
    verify_execution_authorization,
)
from agent_dna.trace import AgentAction

Z = "sha256:" + ("0" * 64)
ONE = "sha256:" + ("1" * 64)
WIRE = b'{"account":"4471","amount":400000,"currency":"INR"}'
PEER = b"tls-spki:payments.store.example:v3"
ORG = "org-demo"
AGENT = "treasury-agent"
ARGS = {"note": "binding-test"}


@pytest.fixture()
def authorize_env(tmp_path, monkeypatch):
    op = generate_key(AGENT, "full")
    other = generate_key("other-agent", "full")
    keys_path = tmp_path / "keys.json"
    keys_path.write_text(
        json.dumps(
            {
                op["hash"]: {"name": op["name"], "scope": "full"},
                other["hash"]: {"name": other["name"], "scope": "full"},
            }
        ),
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
    db_path = tmp_path / "pv.db"

    monkeypatch.setenv("PV_DB_PATH", str(db_path))
    monkeypatch.setenv("PV_API_KEYS_FILE", str(keys_path))
    monkeypatch.setenv("PV_EXECUTION_SIGNER_KEY", str(key_path))
    monkeypatch.setenv("PV_TRUST_BUNDLE", str(bundle_path))
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)

    import api.server as server

    server._pv_signer_cache.clear()
    importlib.reload(server)
    server._pv_signer_cache.clear()

    with TestClient(server.app) as client:
        yield {
            "client": client,
            "key": op["key"],
            "other_key": other["key"],
            "server": server,
            "db_path": db_path,
            "trust_bundle": bundle,
        }


def _ea_action(capability: str = "crm.read_contact", parameters: dict | None = None):
    return {
        "subject_principal": f"{AGENT}@{ORG}",
        "subject_key_id": AGENT,
        "action": capability,
        "resource": "crm:contact",
        "parameters": parameters if parameters is not None else dict(ARGS),
    }


def _dispatch():
    return {
        "transport": "https",
        "destination": "crm.store.example",
        "operation": "GET /v1/contacts",
        "wire_content_type": "application/json",
        "wire_content_encoding": "identity",
        "tool_id": "crm.read_contact.v1",
        "tool_schema_digest": Z,
        "tool_artifact_digest": ONE,
        "credential_audience": "crm.store.example",
        "idempotency_key_digest": Z,
        "retry_policy_digest": ONE,
    }


def _authorize_body(
    *,
    decision_id: str | None = None,
    record_hash: str | None = None,
    decision_receipt_digest: str | None = None,
    action: dict | None = None,
    agent_id: str = AGENT,
):
    digest = decision_receipt_digest or Z
    body: dict = {
        "request_id": "req-binding-1",
        "agent_id": agent_id,
        "organisation_id": ORG,
        "action": action or _ea_action(),
        "dispatch": _dispatch(),
        "expected_wire_bytes_digest": sha256_bytes_digest(WIRE),
        "expected_wire_bytes_length": len(WIRE),
        "expected_peer_identity_digest": sha256_bytes_digest(PEER),
        "decision_receipt_digest": digest,
        "authority_receipt_digest": ONE,
        "state_snapshot_digest": Z,
        "policy_bundle_digest": ONE,
        "obligations_digest": Z,
    }
    if decision_id is not None:
        body["decision_id"] = decision_id
    if record_hash is not None:
        body["record_hash"] = record_hash
    return body


def _decide_allow(client, key: str, capability: str = "crm.read_contact"):
    r = client.post(
        "/v1/decide",
        headers={"X-API-Key": key},
        json={
            "agent_id": AGENT,
            "capability": capability,
            "timestamp": time.time(),
            "arguments": dict(ARGS),
        },
    )
    assert r.status_code == 200, r.text
    record = r.json()["record"]
    return record


def test_omit_decision_reference_fails_closed(authorize_env):
    client, key = authorize_env["client"], authorize_env["key"]
    r = client.post(
        "/v1/authorize",
        headers={"X-API-Key": key},
        json=_authorize_body(),
    )
    assert r.status_code == 422
    assert r.json()["detail"]["reason_code"] == AUTHORIZE_DECISION_REQUIRED
    assert "authorization" not in r.json()


def test_no_stored_allow_refuses_mint(authorize_env):
    client, key = authorize_env["client"], authorize_env["key"]
    r = client.post(
        "/v1/authorize",
        headers={"X-API-Key": key},
        json=_authorize_body(decision_id="decision-does-not-exist"),
    )
    assert r.status_code == 404
    assert r.json()["detail"]["reason_code"] == AUTHORIZE_DECISION_NOT_FOUND


def test_stored_block_refuses_mint(authorize_env):
    client, key = authorize_env["client"], authorize_env["key"]
    server = authorize_env["server"]
    action = AgentAction(
        agent_id=AGENT,
        capability="payments.drain_account",
        timestamp=time.time(),
        arguments=dict(ARGS),
    )
    result = DecisionResult(
        decision=Decision.BLOCK,
        triggered_by="adversarial_fixture",
        reason="forced block for authorize binding",
        capability=action.capability,
        agent_id=AGENT,
        drift_score=1.0,
        severity=Severity.CRITICAL,
    )
    rec = build_record(action, result)
    server.state["store"].append(rec)

    receipt = "sha256:" + rec.record_hash
    r = client.post(
        "/v1/authorize",
        headers={"X-API-Key": key},
        json=_authorize_body(
            decision_id=rec.decision_id,
            decision_receipt_digest=receipt,
            action=_ea_action(capability=action.capability),
        ),
    )
    assert r.status_code == 403
    assert r.json()["detail"]["reason_code"] == AUTHORIZE_DECISION_NOT_ALLOW


def test_allow_for_different_agent_refuses(authorize_env):
    client = authorize_env["client"]
    owner_key = authorize_env["key"]
    other_key = authorize_env["other_key"]
    record = _decide_allow(client, owner_key)
    receipt = "sha256:" + record["record_hash"]
    r = client.post(
        "/v1/authorize",
        headers={"X-API-Key": other_key},
        json=_authorize_body(
            decision_id=record["decision_id"],
            decision_receipt_digest=receipt,
            agent_id="other-agent",
        ),
    )
    assert r.status_code == 403
    assert r.json()["detail"]["reason_code"] == AUTHORIZE_AGENT_MISMATCH


def test_receipt_digest_mismatch_refuses(authorize_env):
    client, key = authorize_env["client"], authorize_env["key"]
    record = _decide_allow(client, key)
    r = client.post(
        "/v1/authorize",
        headers={"X-API-Key": key},
        json=_authorize_body(
            decision_id=record["decision_id"],
            decision_receipt_digest=Z,
        ),
    )
    assert r.status_code == 403
    assert r.json()["detail"]["reason_code"] == AUTHORIZE_RECEIPT_DIGEST_MISMATCH


def test_action_mismatch_refuses(authorize_env):
    client, key = authorize_env["client"], authorize_env["key"]
    record = _decide_allow(client, key)
    receipt = "sha256:" + record["record_hash"]
    r = client.post(
        "/v1/authorize",
        headers={"X-API-Key": key},
        json=_authorize_body(
            decision_id=record["decision_id"],
            decision_receipt_digest=receipt,
            action=_ea_action(capability="crm.update_contact"),
        ),
    )
    assert r.status_code == 403
    assert r.json()["detail"]["reason_code"] == AUTHORIZE_ACTION_MISMATCH


def test_bound_allow_mints_and_wire_tamper_fails_verify(authorize_env):
    """Vector 3: altered wire bytes after authorization refuse at verify."""
    client, key = authorize_env["client"], authorize_env["key"]
    record = _decide_allow(client, key)
    receipt = "sha256:" + record["record_hash"]
    body = _authorize_body(
        decision_id=record["decision_id"],
        record_hash=record["record_hash"],
        decision_receipt_digest=receipt,
    )
    minted = client.post(
        "/v1/authorize",
        headers={"X-API-Key": key},
        json=body,
    )
    assert minted.status_code == 200, minted.text
    payload = minted.json()
    authorization = payload["authorization"]
    store = authorize_env["server"].state["store"]

    tampered = verify_execution_authorization(
        authorization,
        payload["trust_bundle"],
        expected_request_id=body["request_id"],
        expected_action=body["action"],
        expected_dispatch=body["dispatch"],
        expected_decision_receipt_digest=receipt,
        expected_authority_receipt_digest=ONE,
        expected_approval_artifact_digest=None,
        expected_state_snapshot_digest=Z,
        expected_policy_bundle_digest=ONE,
        expected_obligations_digest=Z,
        expected_wire_bytes=b'{"account":"4471","amount":900000}',
        expected_peer_identity_bytes=PEER,
        at_time=payload["at_time"],
        already_consumed=False,
        consume_ledger=store,
    )
    assert not tampered.ok
    assert tampered.reason_code == "EXECUTION_AUTHORIZATION_NON_CONFORMANT"
    assert any("outbound bytes" in f for f in tampered.failures)
    # Digest mismatch must not consume the permit.
    assert not store.is_execution_authorization_consumed(
        authorization["execution_authorization_id"]
    )


def test_bound_allow_action_digest_matches_sha256(authorize_env):
    client, key = authorize_env["client"], authorize_env["key"]
    record = _decide_allow(client, key)
    receipt = "sha256:" + record["record_hash"]
    body = _authorize_body(
        decision_id=record["decision_id"],
        decision_receipt_digest=receipt,
    )
    r = client.post(
        "/v1/authorize",
        headers={"X-API-Key": key},
        json=body,
    )
    assert r.status_code == 200
    auth = r.json()["authorization"]
    assert auth["action_digest"] == sha256_digest(body["action"])
    assert auth["decision_receipt_digest"] == receipt
