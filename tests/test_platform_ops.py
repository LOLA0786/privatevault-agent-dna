"""Platform ops surface: readiness, Prometheus metrics, ops summary."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent_dna.apikeys import generate_key
from tests.decide_binding import decide_json


@pytest.fixture()
def auth_client(tmp_path, monkeypatch):
    op = generate_key("payments-agent", "full")
    au = generate_key("auditor", "audit")
    keys_path = tmp_path / "keys.json"
    keys_path.write_text(
        json.dumps(
            {
                op["hash"]: {"name": op["name"], "scope": "full"},
                au["hash"]: {"name": au["name"], "scope": "audit"},
            }
        ),
        encoding="utf-8",
    )
    grants_path = tmp_path / "grants.json"
    grants_path.write_text(
        json.dumps(
            [
                {
                    "agent_id": "payments-agent",
                    "capability": "crm.read_contact",
                    "granted_by": "test",
                }
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "pv.db"))
    monkeypatch.setenv("PV_API_KEYS_FILE", str(keys_path))
    monkeypatch.setenv("PV_GRANTS_FILE", str(grants_path))
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    import api.server as server

    importlib.reload(server)
    with TestClient(server.app) as client:
        yield client, op["key"], au["key"]


def test_ready_reports_store_and_auth(auth_client):
    client, _op, _au = auth_client
    r = client.get("/ready")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ready"
    assert body["auth_enabled"] is True
    assert body["db_path"]


def test_metrics_count_decisions(auth_client):
    client, op_key, _au = auth_client
    headers = {"X-API-Key": op_key}
    allow = client.post(
        "/v1/decide",
        headers=headers,
        json=decide_json("payments-agent", "crm.read_contact"),
    )
    assert allow.status_code == 200
    client.post(
        "/v1/decide",
        headers=headers,
        json=decide_json("payments-agent", "payments.drain_account"),
    )
    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert "text/plain" in metrics.headers["content-type"]
    text = metrics.text
    assert "pv_decisions_total" in text
    assert 'verdict="allow"' in text or "verdict=" in text


def test_ops_summary_audit_scope(auth_client):
    client, op_key, au_key = auth_client
    client.post(
        "/v1/decide",
        headers={"X-API-Key": op_key},
        json=decide_json("payments-agent", "crm.read_contact"),
    )
    denied = client.get("/v1/ops/summary")
    assert denied.status_code == 401
    ok = client.get("/v1/ops/summary", headers={"X-API-Key": au_key})
    assert ok.status_code == 200
    body = ok.json()
    assert body["metrics"]["total_decisions"] >= 1
    assert "allow" in body["metrics"]["verdict_distribution"]


def test_audit_key_cannot_decide(auth_client):
    client, _op, au_key = auth_client
    r = client.post(
        "/v1/decide",
        headers={"X-API-Key": au_key},
        json=decide_json("auditor", "crm.read_contact"),
    )
    assert r.status_code == 401


def test_platform_demo_script_help():
    script = Path(__file__).resolve().parents[1] / "tools" / "platform_demo.py"
    assert script.is_file()
