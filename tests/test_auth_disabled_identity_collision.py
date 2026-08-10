"""Regression test for authentication-state and agent-name separation."""

import importlib
import json

from fastapi.testclient import TestClient

from agent_dna.apikeys import generate_key
from tests.decide_binding import decide_json


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
            json=decide_json("treasury-payments-agent", "crm.read_contact"),
        )

    assert response.status_code == 403
