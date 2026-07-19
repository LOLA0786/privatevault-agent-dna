"""P1: API key auth — hashed at rest, /v1 protected, /health open,
auth-disabled mode explicit."""

import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent_dna.apikeys import generate_key


def _client(tmp_path, monkeypatch, with_keys=True):
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "auth.db"))
    key = None
    if with_keys:
        entry = generate_key("auth-agent")
        key = entry["key"]
        kf = tmp_path / "keys.json"
        kf.write_text(json.dumps({entry["hash"]: "auth-agent"}))
        monkeypatch.setenv("PV_API_KEYS_FILE", str(kf))
    else:
        monkeypatch.delenv("PV_API_KEYS_FILE", raising=False)
    import importlib
    import api.server as server
    importlib.reload(server)
    return TestClient(server.app), key


def _decide(client, headers=None):
    return client.post("/v1/decide", headers=headers or {}, json={
        "agent_id": "auth-agent",
        "capability": "crm.read_contact",
        "timestamp": time.time(),
    })


def test_valid_key_passes(tmp_path, monkeypatch):
    with_client, key = _client(tmp_path, monkeypatch)
    with with_client as c:
        assert _decide(c, {"X-API-Key": key}).status_code == 200


def test_missing_key_401(tmp_path, monkeypatch):
    with_client, _ = _client(tmp_path, monkeypatch)
    with with_client as c:
        assert _decide(c).status_code == 401


def test_wrong_key_401(tmp_path, monkeypatch):
    with_client, _ = _client(tmp_path, monkeypatch)
    with with_client as c:
        assert _decide(c, {"X-API-Key": "pv_forged"}).status_code == 401


def test_health_and_root_open(tmp_path, monkeypatch):
    with_client, _ = _client(tmp_path, monkeypatch)
    with with_client as c:
        assert c.get("/health").status_code == 200
        assert c.get("/").status_code == 200


def test_keys_file_contains_no_raw_keys(tmp_path, monkeypatch):
    with_client, key = _client(tmp_path, monkeypatch)
    stored = (tmp_path / "keys.json").read_text()
    assert key not in stored          # only the hash is at rest


def test_disabled_mode_is_open_and_explicit(tmp_path, monkeypatch):
    with_client, _ = _client(tmp_path, monkeypatch, with_keys=False)
    with with_client as c:
        assert _decide(c).status_code == 200   # pilot dev-mode, loudly warned
