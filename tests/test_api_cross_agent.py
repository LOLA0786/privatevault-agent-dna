"""CABI dual-control on HTTP POST /v1/decide."""

from __future__ import annotations

import importlib
import json
import time

import pytest
from fastapi.testclient import TestClient

from agent_dna.apikeys import generate_key


@pytest.fixture()
def swarm_client(tmp_path, monkeypatch):
    maker = generate_key("maker-1", "full")
    checker = generate_key("checker-1", "full")
    keys_path = tmp_path / "keys.json"
    keys_path.write_text(
        json.dumps(
            {
                maker["hash"]: {"name": maker["name"], "scope": "full"},
                checker["hash"]: {"name": checker["name"], "scope": "full"},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "pv.db"))
    monkeypatch.setenv("PV_API_KEYS_FILE", str(keys_path))
    monkeypatch.setenv("PV_CROSS_AGENT", "1")
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    import api.server as server

    importlib.reload(server)
    with TestClient(server.app) as client:
        yield client, maker["key"], checker["key"]


def _decide(client, key, agent_id, capability, execution_id):
    return client.post(
        "/v1/decide",
        headers={"X-API-Key": key},
        json={
            "agent_id": agent_id,
            "capability": capability,
            "timestamp": time.time(),
            "execution_id": execution_id,
            "arguments": {"amount": 1000},
        },
    )


def test_runtime_manifest_shows_cross_agent(swarm_client):
    client, maker_key, _ = swarm_client
    r = client.get("/v1/runtime", headers={"X-API-Key": maker_key})
    assert r.status_code == 200
    comp = r.json()["composition"]
    assert comp["cross_agent"]["status"] == "attached"
    assert comp["loop_discovery"]["status"] == "authorize_gated"


def test_same_agent_cannot_initiate_and_approve(swarm_client):
    client, maker_key, _ = swarm_client
    first = _decide(client, maker_key, "maker-1", "payments.initiate_wire", "swarm-1")
    assert first.status_code in (200, 202, 403)
    second = _decide(client, maker_key, "maker-1", "payments.approve_wire", "swarm-1")
    assert second.status_code == 403
    body = second.json()
    assert body["decision"] == "block"
    assert body["triggered_by"] == "cross_agent_invariant"
    assert "maker==checker" in body["reason"]


def test_distinct_checker_can_approve(swarm_client):
    client, maker_key, checker_key = swarm_client
    _decide(client, maker_key, "maker-1", "payments.initiate_wire", "swarm-2")
    ok = _decide(client, checker_key, "checker-1", "payments.approve_wire", "swarm-2")
    # May be allow or require_approval from drift; must not be CABI block
    if ok.status_code == 403:
        assert ok.json().get("triggered_by") != "cross_agent_invariant"
    else:
        assert ok.status_code in (200, 202)


def test_without_execution_id_skips_cabi(swarm_client):
    client, maker_key, _ = swarm_client
    r = client.post(
        "/v1/decide",
        headers={"X-API-Key": maker_key},
        json={
            "agent_id": "maker-1",
            "capability": "payments.initiate_wire",
            "timestamp": time.time(),
        },
    )
    # No execution_id => CABI inert; precedence may still non-allow novel tools
    assert r.status_code in (200, 202, 403)
    if r.status_code == 403:
        assert r.json().get("triggered_by") != "cross_agent_invariant"
