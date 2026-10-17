"""Shared fixture: a real PrivateVault API with a full key, an audit key
and decisions on record."""

from __future__ import annotations

import importlib
import json

import pytest
from fastapi.testclient import TestClient

from agent_dna.apikeys import generate_key
from tests.decide_binding import decide_json


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    """A real API with one full key (agent a1), one audit key and a grant
    for crm.read_contact only; ungranted capabilities are blocked."""
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "audit.db"))
    monkeypatch.delenv("PV_RECEIPT_SIGNING_KEY", raising=False)
    full = generate_key("a1", scope="full")
    audit = generate_key("auditor-1", scope="audit")
    keyfile = tmp_path / "keys.json"
    keyfile.write_text(
        json.dumps(
            {
                full["hash"]: {"name": "a1", "scope": "full"},
                audit["hash"]: {"name": "auditor-1", "scope": "audit"},
            }
        )
    )
    grants = tmp_path / "grants.json"
    grants.write_text(
        json.dumps(
            [{"agent_id": "a1", "capability": "crm.read_contact", "granted_by": "test"}]
        )
    )
    monkeypatch.setenv("PV_API_KEYS_FILE", str(keyfile))
    monkeypatch.setenv("PV_GRANTS_FILE", str(grants))
    monkeypatch.setenv("PV_UNGRANTED_DECISION", "block")

    import api.server as server

    importlib.reload(server)
    with TestClient(server.app) as http:
        for capability in (
            "crm.read_contact",
            "payments.pay_invoice",
            "crm.read_contact",
        ):
            http.post(
                "/v1/decide",
                json=decide_json("a1", capability),
                headers={"X-API-Key": full["key"]},
            )
        export = [
            json.loads(line)
            for line in http.get(
                "/v1/audit/export", headers={"X-API-Key": audit["key"]}
            ).text.splitlines()
            if line.strip()
        ]
        yield {
            "http": http,
            "audit_key": audit["key"],
            "full_key": full["key"],
            "decisions": [r for r in export if r.get("kind", "decision") == "decision"],
        }
