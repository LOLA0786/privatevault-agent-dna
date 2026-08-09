"""Adversarial consume ledger: single-use is durable and atomic."""

from __future__ import annotations

import importlib
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from agent_dna.apikeys import generate_key
from agent_dna.authority_v01 import (
    CANONICALIZATION,
    TRUST_SPEC,
    encode_public_key,
)
from agent_dna.authorize_binding import EXECUTION_AUTHORIZATION_CONSUMED
from agent_dna.execution_v01 import (
    sha256_bytes_digest,
    verify_execution_authorization,
)
from agent_dna.sqlite_store import SQLiteDecisionStore

Z = "sha256:" + ("0" * 64)
ONE = "sha256:" + ("1" * 64)
WIRE = b'{"account":"4471","amount":400000,"currency":"INR"}'
PEER = b"tls-spki:payments.store.example:v3"
ORG = "org-demo"
AGENT = "treasury-agent"
ARGS = {"note": "consume-test"}


@pytest.fixture()
def consume_env(tmp_path, monkeypatch):
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
            "server": server,
            "db_path": db_path,
        }


def _ea_action():
    return {
        "subject_principal": f"{AGENT}@{ORG}",
        "subject_key_id": AGENT,
        "action": "crm.read_contact",
        "resource": "crm:contact",
        "parameters": dict(ARGS),
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


def _mint(client, key: str):
    decided = client.post(
        "/v1/decide",
        headers={"X-API-Key": key},
        json={
            "agent_id": AGENT,
            "capability": "crm.read_contact",
            "timestamp": time.time(),
            "arguments": dict(ARGS),
        },
    )
    assert decided.status_code == 200, decided.text
    record = decided.json()["record"]
    receipt = "sha256:" + record["record_hash"]
    action = _ea_action()
    dispatch = _dispatch()
    body = {
        "request_id": f"req-consume-{record['decision_id'][:8]}",
        "agent_id": AGENT,
        "organisation_id": ORG,
        "decision_id": record["decision_id"],
        "action": action,
        "dispatch": dispatch,
        "expected_wire_bytes_digest": sha256_bytes_digest(WIRE),
        "expected_wire_bytes_length": len(WIRE),
        "expected_peer_identity_digest": sha256_bytes_digest(PEER),
        "decision_receipt_digest": receipt,
        "authority_receipt_digest": ONE,
        "state_snapshot_digest": Z,
        "policy_bundle_digest": ONE,
        "obligations_digest": Z,
    }
    minted = client.post(
        "/v1/authorize",
        headers={"X-API-Key": key},
        json=body,
    )
    assert minted.status_code == 200, minted.text
    payload = minted.json()
    return {
        "authorization": payload["authorization"],
        "trust_bundle": payload["trust_bundle"],
        "at_time": payload["at_time"],
        "body": body,
        "receipt": receipt,
    }


def _verify(minted, store, *, already_consumed: bool = False, wire=WIRE):
    body = minted["body"]
    return verify_execution_authorization(
        minted["authorization"],
        minted["trust_bundle"],
        expected_request_id=body["request_id"],
        expected_action=body["action"],
        expected_dispatch=body["dispatch"],
        expected_decision_receipt_digest=minted["receipt"],
        expected_authority_receipt_digest=ONE,
        expected_approval_artifact_digest=None,
        expected_state_snapshot_digest=Z,
        expected_policy_bundle_digest=ONE,
        expected_obligations_digest=Z,
        expected_wire_bytes=wire,
        expected_peer_identity_bytes=PEER,
        at_time=minted["at_time"],
        already_consumed=already_consumed,
        consume_ledger=store,
    )


def test_second_verify_refused_as_consumed(consume_env):
    client, key = consume_env["client"], consume_env["key"]
    store = consume_env["server"].state["store"]
    minted = _mint(client, key)

    first = _verify(minted, store)
    assert first.ok

    second = _verify(minted, store)
    assert not second.ok
    assert second.reason_code == EXECUTION_AUTHORIZATION_CONSUMED
    assert any("already been consumed" in f for f in second.failures)


def test_consume_survives_process_restart(consume_env):
    """Vector 2: restart between verifies; second still refused."""
    client, key = consume_env["client"], consume_env["key"]
    store = consume_env["server"].state["store"]
    db_path = consume_env["db_path"]
    minted = _mint(client, key)

    first = _verify(minted, store)
    assert first.ok
    auth_id = minted["authorization"]["execution_authorization_id"]
    assert store.is_execution_authorization_consumed(auth_id)

    store.close()
    restarted = SQLiteDecisionStore(db_path)
    try:
        assert restarted.is_execution_authorization_consumed(auth_id)
        second = _verify(minted, restarted)
        assert not second.ok
        assert second.reason_code == EXECUTION_AUTHORIZATION_CONSUMED
    finally:
        restarted.close()


def test_caller_attestation_cannot_relax_ledger(consume_env):
    client, key = consume_env["client"], consume_env["key"]
    store = consume_env["server"].state["store"]
    minted = _mint(client, key)
    assert _verify(minted, store).ok

    # already_consumed=False must not override durable consume.
    replay = _verify(minted, store, already_consumed=False)
    assert not replay.ok
    assert replay.reason_code == EXECUTION_AUTHORIZATION_CONSUMED


def test_caller_attestation_tightens_without_ledger_row(consume_env):
    client, key = consume_env["client"], consume_env["key"]
    store = consume_env["server"].state["store"]
    minted = _mint(client, key)
    auth_id = minted["authorization"]["execution_authorization_id"]

    refused = _verify(minted, store, already_consumed=True)
    assert not refused.ok
    assert refused.reason_code == EXECUTION_AUTHORIZATION_CONSUMED
    # Tightening path does not insert a ledger row.
    assert not store.is_execution_authorization_consumed(auth_id)


def test_concurrent_verifies_only_one_consumes(consume_env):
    client, key = consume_env["client"], consume_env["key"]
    store = consume_env["server"].state["store"]
    minted = _mint(client, key)
    barrier = threading.Barrier(8)
    results: list[bool] = []

    def _race() -> None:
        # Each thread needs its own store connection (thread-local).
        local = SQLiteDecisionStore(consume_env["db_path"])
        try:
            barrier.wait()
            report = _verify(minted, local)
            results.append(report.ok)
        finally:
            local.close()

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(_race) for _ in range(8)]
        for fut in futures:
            fut.result()

    assert results.count(True) == 1
    assert results.count(False) == 7
    assert store.is_execution_authorization_consumed(
        minted["authorization"]["execution_authorization_id"]
    )
