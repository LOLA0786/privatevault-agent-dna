"""API contract: HTTP status IS the enforcement signal; every decision
persists; audit export passes the independent verifier."""

import subprocess
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

VERIFIER = Path(__file__).resolve().parent.parent / "tools" / "verify_records.py"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "pv.db"))
    # import after env is set so DB_PATH picks it up
    import importlib

    import api.server as server

    importlib.reload(server)
    with TestClient(server.app) as c:
        yield c


def _decide(client, capability, agent="api-agent-01"):
    return client.post(
        "/v1/decide",
        json={
            "agent_id": agent,
            "capability": capability,
            "timestamp": time.time(),
            "arguments": {"note": "test"},
        },
    )


def test_allow_returns_200_with_sealed_record(client):
    # capabilities from the synthetic training profile
    r = _decide(client, "crm.read_contact")
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "allow"
    assert body["record"]["record_hash"]
    assert body["record"]["outcome"] == "pending"


def test_novel_capability_returns_non_200(client):
    _decide(client, "crm.read_contact")
    r = _decide(client, "payments.drain_account")
    assert r.status_code in (202, 403)
    assert r.json()["decision"] in ("require_approval", "block")


def test_outcome_roundtrip_and_conflict(client):
    r = _decide(client, "crm.read_contact")
    did = r.json()["record"]["decision_id"]

    ok = client.post(
        "/v1/outcome",
        json={
            "decision_id": did,
            "status": "ok",
        },
    )
    assert ok.status_code == 200
    assert ok.json()["event"]["decision_ref"] == did

    dup = client.post(
        "/v1/outcome",
        json={
            "decision_id": did,
            "status": "error",
        },
    )
    assert dup.status_code == 409  # one execution per decision


def test_queries(client):
    _decide(client, "crm.read_contact")
    _decide(client, "crm.enrich_contact")
    r = client.get("/v1/records/api-agent-01")
    assert len(r.json()["records"]) == 2

    lineage_target = r.json()["records"][-1]["decision_id"]
    lin = client.get(f"/v1/lineage/{lineage_target}")
    assert lin.status_code == 200
    assert len(lin.json()["lineage"]) >= 1

    assert client.get("/v1/lineage/nonexistent").status_code == 404


def test_verify_and_audit_export(client, tmp_path):
    _decide(client, "crm.read_contact")
    r = _decide(client, "crm.update_contact")
    client.post(
        "/v1/outcome",
        json={
            "decision_id": r.json()["record"]["decision_id"],
            "status": "ok",
        },
    )

    v = client.get("/v1/verify")
    assert v.json()["chains"] == {"api-agent-01": True}

    exp = client.get("/v1/audit/export")
    assert exp.status_code == 200
    audit = tmp_path / "audit.jsonl"
    audit.write_bytes(exp.content)

    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(audit)],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout
    assert "VERDICT: PASS" in proc.stdout
