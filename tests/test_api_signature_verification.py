"""The API verifier separates chain integrity from trusted signatures."""

import json

from fastapi.testclient import TestClient

from agent_dna.signer import ReceiptSigner, generate_keypair
from tests.decide_binding import decide_json

RUNTIME_KEYS = generate_keypair()


def _client(tmp_path, monkeypatch, *, signed: bool):
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "verify.db"))
    monkeypatch.setenv("PV_ALLOW_NO_AUTH", "1")
    monkeypatch.delenv("PV_API_KEYS_FILE", raising=False)

    if signed:
        monkeypatch.setenv(
            "PV_RECEIPT_SIGNING_KEY",
            RUNTIME_KEYS["signing_key"],
        )
        monkeypatch.setenv(
            "PV_TRUSTED_PUBLIC_KEYS",
            RUNTIME_KEYS["public_key"],
        )
    else:
        monkeypatch.delenv("PV_RECEIPT_SIGNING_KEY", raising=False)
        monkeypatch.delenv("PV_TRUSTED_PUBLIC_KEYS", raising=False)

    import importlib

    import api.server as server

    importlib.reload(server)
    return server, TestClient(server.app)


def _create_record(client: TestClient) -> str:
    response = client.post(
        "/v1/decide",
        json=decide_json("verify-agent", "crm.read_contact"),
    )
    assert response.status_code in {200, 202, 403}
    return response.json()["record"]["record_hash"]


def test_verify_reports_trusted_signatures(tmp_path, monkeypatch):
    _, client = _client(tmp_path, monkeypatch, signed=True)

    with client:
        _create_record(client)
        result = client.get("/v1/verify").json()

    assert result["chain_integrity_verified"] is True
    assert result["signatures"] == {
        "mode": "trusted",
        "trusted_key_count": 1,
        "records_seen": 1,
        "valid_envelopes": 1,
        "missing_envelopes": 0,
        "invalid_envelopes": 0,
        "verified": True,
    }


def test_verify_rejects_self_attested_attacker_envelope(
    tmp_path,
    monkeypatch,
):
    server, client = _client(tmp_path, monkeypatch, signed=True)

    with client:
        record_hash = _create_record(client)

        attacker_keys = generate_keypair()
        forged = (
            ReceiptSigner(seed_hex=attacker_keys["signing_key"])
            .sign_hash(record_hash)
            .to_dict()
        )

        server.state["store"]._conn.execute(
            "UPDATE envelopes SET envelope = ? WHERE record_hash = ?",
            (
                json.dumps(forged, sort_keys=True, separators=(",", ":")),
                record_hash,
            ),
        )
        server.state["store"]._conn.commit()

        signatures = client.get("/v1/verify").json()["signatures"]

    assert signatures["valid_envelopes"] == 0
    assert signatures["invalid_envelopes"] == 1
    assert signatures["verified"] is False


def test_verify_detects_missing_envelope(tmp_path, monkeypatch):
    server, client = _client(tmp_path, monkeypatch, signed=True)

    with client:
        record_hash = _create_record(client)
        server.state["store"]._conn.execute(
            "DELETE FROM envelopes WHERE record_hash = ?",
            (record_hash,),
        )
        server.state["store"]._conn.commit()

        signatures = client.get("/v1/verify").json()["signatures"]

    assert signatures["missing_envelopes"] == 1
    assert signatures["invalid_envelopes"] == 0
    assert signatures["verified"] is False


def test_unsigned_runtime_does_not_claim_signature_verification(
    tmp_path,
    monkeypatch,
):
    _, client = _client(tmp_path, monkeypatch, signed=False)

    with client:
        _create_record(client)
        signatures = client.get("/v1/verify").json()["signatures"]

    assert signatures["mode"] == "disabled"
    assert signatures["records_seen"] == 1
    assert signatures["trusted_key_count"] == 0
    assert signatures["verified"] is None
