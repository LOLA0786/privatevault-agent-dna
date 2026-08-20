"""Mint replay must return the original stored trust bundle pair."""

from __future__ import annotations

import json

import pytest
from nacl.signing import SigningKey

from agent_dna.authority_v01 import (
    CANONICALIZATION,
    TRUST_SPEC,
    encode_public_key,
    sha256_digest,
)
from agent_dna.execution_v01 import verify_execution_authorization
from agent_dna.sqlite_store import SQLiteDecisionStore
from tests.test_authorize_mint_claim import (
    ONE,
    ORG,
    PEER,
    WIRE,
    Z,
    _authorize_body,
    _decide_allow,
    build_mint_env,
)


@pytest.fixture
def mint_env(tmp_path, monkeypatch):
    yield from build_mint_env(tmp_path, monkeypatch)


def test_replay_returns_stored_trust_bundle_not_current_bundle(mint_env) -> None:
    client, key = mint_env["client"], mint_env["key"]
    record = _decide_allow(client, key)
    body = _authorize_body(record)
    first = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
    assert first.status_code == 200, first.text
    original_auth = first.json()["authorization"]
    original_bundle = first.json()["trust_bundle"]
    original_digest = original_auth["trust_bundle_digest"]
    assert sha256_digest(original_bundle) == original_digest

    rotated = SigningKey.generate()
    mint_env["key_path"].write_bytes(bytes(rotated))
    new_bundle = {
        "spec": TRUST_SPEC,
        "canonicalization": CANONICALIZATION,
        "organisation_id": ORG,
        "bundle_version": 2,
        "pinned_at": "2026-08-20T12:00:00Z",
        "keys": [
            {
                "key_id": "k-rotated",
                "principal": f"execution-runtime@{ORG}",
                "algorithm": "ed25519",
                "public_key": encode_public_key(rotated),
                "usages": ["execution_authorization_signer"],
            }
        ],
    }
    mint_env["bundle_path"].write_text(json.dumps(new_bundle), encoding="utf-8")
    mint_env["server"]._pv_signer_cache.clear()

    replay = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
    assert replay.status_code == 200, replay.text
    replayed_auth = replay.json()["authorization"]
    replayed_bundle = replay.json()["trust_bundle"]
    assert replayed_auth == original_auth
    assert replayed_bundle == original_bundle
    assert sha256_digest(replayed_bundle) == original_digest
    assert sha256_digest(replayed_bundle) == replayed_auth["trust_bundle_digest"]
    assert sha256_digest(new_bundle) != original_digest
    report = verify_execution_authorization(
        replayed_auth,
        replayed_bundle,
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
        at_time=replay.json()["at_time"],
        already_consumed=False,
    )
    assert report.ok, report


def test_legacy_mint_row_without_bundle_fails_closed(mint_env) -> None:
    client, key = mint_env["client"], mint_env["key"]
    record = _decide_allow(client, key)
    body = _authorize_body(record)
    first = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
    assert first.status_code == 200, first.text
    auth_id = first.json()["authorization"]["execution_authorization_id"]
    conn = mint_env["server"].state["store"]._conn
    cols = [
        row[1]
        for row in conn.execute("PRAGMA table_info(execution_authorization_mint)")
    ]
    if "trust_bundle_json" in cols:
        conn.execute(
            "UPDATE execution_authorization_mint "
            "SET trust_bundle_json = NULL, trust_bundle_digest = NULL "
            "WHERE execution_authorization_id = ?",
            (auth_id,),
        )
        conn.commit()
    replay = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
    assert replay.status_code in {409, 422, 503}
    payload = replay.json()
    assert "authorization" not in payload
    reason = payload["detail"]["reason_code"]
    assert reason == "AUTHORIZE_PERMIT_TRUST_BUNDLE_MISSING"


def test_trust_bundle_pair_survives_restart_after_signer_change(mint_env) -> None:
    client, key = mint_env["client"], mint_env["key"]
    db_path = mint_env["db_path"]
    record = _decide_allow(client, key)
    body = _authorize_body(record)
    first = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
    assert first.status_code == 200, first.text
    original_auth = first.json()["authorization"]
    original_bundle = first.json()["trust_bundle"]
    mint_env["server"].state["store"].close()

    rotated = SigningKey.generate()
    mint_env["key_path"].write_bytes(bytes(rotated))
    mint_env["bundle_path"].write_text(
        json.dumps(
            {
                "spec": TRUST_SPEC,
                "canonicalization": CANONICALIZATION,
                "organisation_id": ORG,
                "bundle_version": 9,
                "pinned_at": "2026-08-20T12:00:00Z",
                "keys": [
                    {
                        "key_id": "k-restart",
                        "principal": f"execution-runtime@{ORG}",
                        "algorithm": "ed25519",
                        "public_key": encode_public_key(rotated),
                        "usages": ["execution_authorization_signer"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    restarted = SQLiteDecisionStore(db_path)
    try:
        row = restarted._conn.execute(
            "SELECT authorization_json, trust_bundle_json, trust_bundle_digest "
            "FROM execution_authorization_mint WHERE decision_id = ?",
            (record["decision_id"],),
        ).fetchone()
        assert row is not None
        stored_auth = json.loads(row[0])
        assert stored_auth["nonce"] == original_auth["nonce"]
        assert row[1], "stored trust bundle must survive restart"
        stored_bundle = json.loads(row[1])
        assert stored_bundle == original_bundle
        assert row[2] == original_auth["trust_bundle_digest"]
        assert sha256_digest(stored_bundle) == stored_auth["trust_bundle_digest"]
    finally:
        restarted.close()
