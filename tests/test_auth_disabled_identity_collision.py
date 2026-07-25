"""Regression test for authentication-state and agent-name separation."""

import importlib
import json
import time

from fastapi.testclient import TestClient

from agent_dna.apikeys import generate_key


def test_key_named_auth_disabled_cannot_impersonate_agent(tmp_path, monkeypatch):
    entry = generate_key("auth-disabled")
    key_file = tmp_path / "keys.json"
    key_file.write_text(json.dumps({entry["hash"]: entry["name"]}))

    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "privatevault.db"))
    monkeypatch.setenv("PV_API_KEYS_FILE", str(key_file))
    monkeypatch.delenv("PV_RECEIPT_SIGNING_KEY", raising=False)

    import api.server as server

    importlib.reload(server)

    with TestClient(server.app) as client:
        response = client.post(
            "/v1/decide",
            headers={"X-API-Key": entry["key"]},
            json={
                "agent_id": "treasury-payments-agent",
                "capability": "crm.read_contact",
                "timestamp": time.time(),
            },
        )

    assert response.status_code == 403
