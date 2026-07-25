"""P4: signing in the serving path — env-keyed, envelopes retrievable,
unsigned mode explicit."""

import time

from fastapi.testclient import TestClient

from agent_dna.signer import generate_keypair, verify_envelope

KEYS = generate_keypair()


def _client(tmp_path, monkeypatch, signed=True):
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "sig.db"))
    monkeypatch.delenv("PV_API_KEYS_FILE", raising=False)
    if signed:
        monkeypatch.setenv("PV_RECEIPT_SIGNING_KEY", KEYS["signing_key"])
        monkeypatch.setenv("PV_TRUSTED_PUBLIC_KEYS", KEYS["public_key"])
    else:
        monkeypatch.delenv("PV_RECEIPT_SIGNING_KEY", raising=False)
        monkeypatch.delenv("PV_TRUSTED_PUBLIC_KEYS", raising=False)
    import importlib

    import api.server as server

    importlib.reload(server)
    return TestClient(server.app)


def _decide(c):
    return c.post(
        "/v1/decide",
        json={
            "agent_id": "sig-agent",
            "capability": "crm.read_contact",
            "timestamp": time.time(),
        },
    )


def test_signed_mode_envelope_verifies(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch) as c:
        assert c.get("/").json()["signing"]["public_key"] == KEYS["public_key"]

        rh = _decide(c).json()["record"]["record_hash"]
        env = c.get(f"/v1/envelope/{rh}").json()["envelope"]
        assert verify_envelope(env, rh)


def test_unsigned_mode_is_explicit(tmp_path, monkeypatch):
    with _client(tmp_path, monkeypatch, signed=False) as c:
        assert c.get("/").json()["signing"] == "disabled"
        rh = _decide(c).json()["record"]["record_hash"]
        assert c.get(f"/v1/envelope/{rh}").status_code == 404
