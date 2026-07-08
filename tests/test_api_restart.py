"""P3: the HTTP service survives restarts — decisions made across two
process lifetimes form one intact, exportable, independently
verifiable chain."""

import subprocess
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

VERIFIER = Path(__file__).resolve().parent.parent / "tools" / "verify_records.py"


def _client(db_path, monkeypatch):
    monkeypatch.setenv("PV_DB_PATH", str(db_path))
    import importlib
    import api.server as server
    importlib.reload(server)
    return TestClient(server.app)


def _decide(client, cap):
    return client.post("/v1/decide", json={
        "agent_id": "restart-agent",
        "capability": cap,
        "timestamp": time.time(),
    })


def test_api_restart_continues_chain(tmp_path, monkeypatch):
    db = tmp_path / "api.db"

    # ---- lifetime 1 ----
    with _client(db, monkeypatch) as c1:
        r = _decide(c1, "crm.read_contact")
        assert r.status_code == 200
        first_hash = r.json()["record"]["record_hash"]

    # ---- lifetime 2 (fresh app over same DB) ----
    with _client(db, monkeypatch) as c2:
        r2 = _decide(c2, "crm.update_contact")
        assert r2.json()["record"]["prev_hash"] == first_hash, (
            "API restart chained from GENESIS"
        )

        v = c2.get("/v1/verify")
        assert v.json()["chains"] == {"restart-agent": True}

        exp = c2.get("/v1/audit/export")
        audit = tmp_path / "audit.jsonl"
        audit.write_bytes(exp.content)

    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(audit)],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stdout
    assert "VERDICT: PASS" in proc.stdout
