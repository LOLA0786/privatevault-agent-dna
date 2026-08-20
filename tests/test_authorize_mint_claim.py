"""PV-02: one decision mints one stored execution authorization."""

from __future__ import annotations

import importlib
import json
import multiprocessing
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from agent_dna.apikeys import generate_key
from agent_dna.authority_v01 import CANONICALIZATION, TRUST_SPEC, encode_public_key
from agent_dna.execution_v01 import sha256_bytes_digest, verify_execution_authorization
from agent_dna.sqlite_store import SQLiteDecisionStore
from tests.decide_binding import decide_json, dispatch_context_for

Z = "sha256:" + ("0" * 64)
ONE = "sha256:" + ("1" * 64)
WIRE = b'{"account":"4471","amount":400000,"currency":"INR"}'
PEER = b"tls-spki:payments.store.example:v3"
ORG = "org-demo"
AGENT = "treasury-agent"
ARGS = {"note": "mint-claim"}

AUTHORIZE_PERMIT_BINDING_CONFLICT = "AUTHORIZE_PERMIT_BINDING_CONFLICT"
AUTHORIZE_PERMIT_ALREADY_CONSUMED = "AUTHORIZE_PERMIT_ALREADY_CONSUMED"
AUTHORIZE_PERMIT_EXPIRED = "AUTHORIZE_PERMIT_EXPIRED"
AUTHORIZE_PERMIT_INDETERMINATE = "AUTHORIZE_PERMIT_INDETERMINATE"


def _canonical(auth: dict) -> str:
    return json.dumps(auth, sort_keys=True, separators=(",", ":"))


def build_mint_env(tmp_path, monkeypatch):
    op = generate_key(AGENT, "full")
    other = generate_key(AGENT, "full")
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
    grants_path = tmp_path / "grants.json"
    grants_path.write_text(
        json.dumps(
            [
                {
                    "agent_id": AGENT,
                    "capability": "crm.read_contact",
                    "granted_by": "test",
                }
            ]
        ),
        encoding="utf-8",
    )
    db_path = tmp_path / "pv.db"
    monkeypatch.setenv("PV_DB_PATH", str(db_path))
    monkeypatch.setenv("PV_API_KEYS_FILE", str(keys_path))
    monkeypatch.setenv("PV_EXECUTION_SIGNER_KEY", str(key_path))
    monkeypatch.setenv("PV_TRUST_BUNDLE", str(bundle_path))
    monkeypatch.setenv("PV_GRANTS_FILE", str(grants_path))
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
            "key_path": key_path,
            "keys_path": keys_path,
            "bundle_path": bundle_path,
            "grants_path": grants_path,
        }


@pytest.fixture()
def mint_env(tmp_path, monkeypatch):
    yield from build_mint_env(tmp_path, monkeypatch)


def _ea_action(parameters: dict | None = None):
    return {
        "subject_principal": f"{AGENT}@{ORG}",
        "subject_key_id": AGENT,
        "action": "crm.read_contact",
        "resource": "crm:contact",
        "parameters": dict(parameters if parameters is not None else ARGS),
    }


def _dispatch(**overrides):
    body = {
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
    body.update(overrides)
    return body


def _authorize_body(record, *, wire=WIRE, peer=PEER, dispatch=None, action=None):
    return {
        "request_id": f"req-mint-{record['decision_id'][:8]}",
        "agent_id": AGENT,
        "organisation_id": ORG,
        "decision_id": record["decision_id"],
        "record_hash": record["record_hash"],
        "action": action or _ea_action(),
        "dispatch": dispatch or _dispatch(),
        "expected_wire_bytes_digest": sha256_bytes_digest(wire),
        "expected_wire_bytes_length": len(wire),
        "expected_peer_identity_digest": sha256_bytes_digest(peer),
        "decision_receipt_digest": "sha256:" + record["record_hash"],
        "authority_receipt_digest": ONE,
        "state_snapshot_digest": Z,
        "policy_bundle_digest": ONE,
        "obligations_digest": Z,
    }


def _decide_allow(client, key: str):
    r = client.post(
        "/v1/decide",
        headers={"X-API-Key": key},
        json=decide_json(
            AGENT,
            "crm.read_contact",
            arguments=dict(ARGS),
            resource="crm:contact",
            org=ORG,
            dispatch_context=dispatch_context_for(
                adapter="https",
                transport="https",
                operation="GET /v1/contacts",
                destination="crm.store.example",
                wire_content_type="application/json",
            ),
        ),
    )
    assert r.status_code == 200, r.text
    return r.json()["record"]


def test_sequential_mint_returns_byte_identical_authorization(mint_env) -> None:
    client, key = mint_env["client"], mint_env["key"]
    record = _decide_allow(client, key)
    body = _authorize_body(record)
    first = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
    body["request_id"] = "req-replay-different-correlation"
    second = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
    assert first.status_code == 200, first.text
    assert second.status_code == 200, second.text
    a1 = first.json()["authorization"]
    a2 = second.json()["authorization"]
    assert a1["execution_authorization_id"] == a2["execution_authorization_id"]
    assert a1["nonce"] == a2["nonce"]
    assert a1["signature"] == a2["signature"]
    assert _canonical(a1) == _canonical(a2)


def test_changed_wire_digest_is_binding_conflict(mint_env) -> None:
    client, key = mint_env["client"], mint_env["key"]
    record = _decide_allow(client, key)
    first = client.post(
        "/v1/authorize",
        headers={"X-API-Key": key},
        json=_authorize_body(record),
    )
    assert first.status_code == 200, first.text
    tampered = client.post(
        "/v1/authorize",
        headers={"X-API-Key": key},
        json=_authorize_body(record, wire=b'{"account":"0000"}'),
    )
    assert tampered.status_code == 403, tampered.text
    assert tampered.json()["detail"]["reason_code"] == AUTHORIZE_PERMIT_BINDING_CONFLICT
    assert "authorization" not in tampered.json()


def test_changed_peer_and_audience_are_binding_conflicts(mint_env) -> None:
    client, key = mint_env["client"], mint_env["key"]
    record = _decide_allow(client, key)
    assert (
        client.post(
            "/v1/authorize",
            headers={"X-API-Key": key},
            json=_authorize_body(record),
        ).status_code
        == 200
    )
    peer = client.post(
        "/v1/authorize",
        headers={"X-API-Key": key},
        json=_authorize_body(record, peer=b"tls-spki:other"),
    )
    assert peer.json()["detail"]["reason_code"] == AUTHORIZE_PERMIT_BINDING_CONFLICT
    audience = client.post(
        "/v1/authorize",
        headers={"X-API-Key": key},
        json=_authorize_body(
            record, dispatch=_dispatch(credential_audience="other.example")
        ),
    )
    assert audience.json()["detail"]["reason_code"] == AUTHORIZE_PERMIT_BINDING_CONFLICT


def test_different_authenticated_principal_is_binding_conflict(mint_env) -> None:
    client, key, other = mint_env["client"], mint_env["key"], mint_env["other_key"]
    record = _decide_allow(client, key)
    assert (
        client.post(
            "/v1/authorize",
            headers={"X-API-Key": key},
            json=_authorize_body(record),
        ).status_code
        == 200
    )
    r = client.post(
        "/v1/authorize",
        headers={"X-API-Key": other},
        json=_authorize_body(record),
    )
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["reason_code"] == AUTHORIZE_PERMIT_BINDING_CONFLICT


def test_consumed_permit_is_not_replaced(mint_env) -> None:
    client, key = mint_env["client"], mint_env["key"]
    store = mint_env["server"].state["store"]
    record = _decide_allow(client, key)
    body = _authorize_body(record)
    minted = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
    payload = minted.json()
    report = verify_execution_authorization(
        payload["authorization"],
        payload["trust_bundle"],
        expected_request_id=body["request_id"],
        expected_action=body["action"],
        expected_dispatch=body["dispatch"],
        expected_decision_receipt_digest=body["decision_receipt_digest"],
        expected_authority_receipt_digest=ONE,
        expected_approval_artifact_digest=None,
        expected_state_snapshot_digest=Z,
        expected_policy_bundle_digest=ONE,
        expected_obligations_digest=Z,
        expected_wire_bytes=WIRE,
        expected_peer_identity_bytes=PEER,
        at_time=payload["at_time"],
        already_consumed=False,
        consume_ledger=store,
    )
    assert report.ok
    replay = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
    assert replay.status_code == 409, replay.text
    assert replay.json()["detail"]["reason_code"] == AUTHORIZE_PERMIT_ALREADY_CONSUMED
    assert "authorization" not in replay.json()


def test_expired_permit_is_not_replaced(mint_env) -> None:
    client, key = mint_env["client"], mint_env["key"]
    record = _decide_allow(client, key)
    body = _authorize_body(record)
    minted = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
    assert minted.status_code == 200, minted.text
    auth_id = minted.json()["authorization"]["execution_authorization_id"]
    conn = mint_env["server"].state["store"]._conn
    conn.execute(
        "UPDATE execution_authorization_mint SET expires_at = ? "
        "WHERE execution_authorization_id = ?",
        ("2020-01-01T00:00:00Z", auth_id),
    )
    conn.commit()
    replay = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
    assert replay.status_code == 409, replay.text
    assert replay.json()["detail"]["reason_code"] == AUTHORIZE_PERMIT_EXPIRED
    assert "authorization" not in replay.json()


def test_indeterminate_outcome_does_not_unlock_remint(mint_env) -> None:
    client, key = mint_env["client"], mint_env["key"]
    record = _decide_allow(client, key)
    body = _authorize_body(record)
    minted = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
    assert minted.status_code == 200, minted.text
    outcome = client.post(
        "/v1/outcome",
        headers={"X-API-Key": key},
        json={
            "decision_id": record["decision_id"],
            "status": "indeterminate",
            "detail": "write began",
        },
    )
    assert outcome.status_code == 200, outcome.text
    replay = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
    assert replay.status_code == 409, replay.text
    assert replay.json()["detail"]["reason_code"] == AUTHORIZE_PERMIT_INDETERMINATE
    assert "authorization" not in replay.json()


def test_mint_claim_survives_store_restart(mint_env) -> None:
    client, key = mint_env["client"], mint_env["key"]
    db_path = mint_env["db_path"]
    record = _decide_allow(client, key)
    body = _authorize_body(record)
    first = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
    assert first.status_code == 200, first.text
    original = first.json()["authorization"]
    mint_env["server"].state["store"].close()
    restarted = SQLiteDecisionStore(db_path)
    try:
        row = restarted._conn.execute(
            "SELECT authorization_json FROM execution_authorization_mint "
            "WHERE decision_id = ?",
            (record["decision_id"],),
        ).fetchone()
        assert row is not None
        stored = json.loads(row[0])
        assert (
            stored["execution_authorization_id"]
            == original["execution_authorization_id"]
        )
        assert stored["nonce"] == original["nonce"]
        assert stored["signature"] == original["signature"]
    finally:
        restarted.close()


def test_concurrent_http_mints_converge(mint_env) -> None:
    client, key = mint_env["client"], mint_env["key"]
    record = _decide_allow(client, key)
    body = _authorize_body(record)
    barrier = threading.Barrier(8)
    ids: list[str] = []
    payloads: list[str] = []

    def _race() -> None:
        barrier.wait()
        r = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
        assert r.status_code == 200, r.text
        auth = r.json()["authorization"]
        ids.append(auth["execution_authorization_id"])
        payloads.append(_canonical(auth))

    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = [pool.submit(_race) for _ in range(8)]
        for fut in futs:
            fut.result()
    assert len(set(ids)) == 1
    assert len(set(payloads)) == 1


def _subprocess_mint(payload: dict) -> dict:
    import os

    os.environ["PV_DB_PATH"] = payload["db_path"]
    os.environ["PV_API_KEYS_FILE"] = payload["keys_path"]
    os.environ["PV_EXECUTION_SIGNER_KEY"] = payload["key_path"]
    os.environ["PV_TRUST_BUNDLE"] = payload["bundle_path"]
    os.environ["PV_GRANTS_FILE"] = payload["grants_path"]
    os.environ.pop("PV_ALLOW_NO_AUTH", None)
    import api.server as server

    server._pv_signer_cache.clear()
    importlib.reload(server)
    server._pv_signer_cache.clear()
    with TestClient(server.app) as client:
        r = client.post(
            "/v1/authorize",
            headers={"X-API-Key": payload["key"]},
            json=payload["body"],
        )
        return {"status": r.status_code, "body": r.json()}


def test_two_processes_do_not_mint_different_permits(mint_env) -> None:
    client, key = mint_env["client"], mint_env["key"]
    record = _decide_allow(client, key)
    body = _authorize_body(record)
    payload = {
        "db_path": str(mint_env["db_path"]),
        "keys_path": str(mint_env["keys_path"]),
        "key_path": str(mint_env["key_path"]),
        "bundle_path": str(mint_env["bundle_path"]),
        "grants_path": str(mint_env["grants_path"]),
        "key": key,
        "body": body,
    }
    ctx = multiprocessing.get_context("spawn")
    with ctx.Pool(2) as pool:
        results = pool.map(_subprocess_mint, [payload, payload])
    assert all(item["status"] == 200 for item in results), results
    ids = [
        item["body"]["authorization"]["execution_authorization_id"] for item in results
    ]
    assert ids[0] == ids[1]
    assert _canonical(results[0]["body"]["authorization"]) == _canonical(
        results[1]["body"]["authorization"]
    )
