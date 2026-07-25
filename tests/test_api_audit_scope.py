"""Audit-scoped API keys through the real HTTP surface: an
audit-scoped key can read /v1/verify and /v1/audit/export, but MUST
be rejected on /v1/decide and every enforcement endpoint. A full-scope
key can do both."""

import json
import time

from fastapi.testclient import TestClient

from agent_dna.apikeys import generate_key


def _client_with_scoped_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "audit.db"))
    monkeypatch.delenv("PV_RECEIPT_SIGNING_KEY", raising=False)

    full_entry = generate_key("a1", scope="full")
    audit_entry = generate_key("auditor-1", scope="audit")

    keyfile = tmp_path / "keys.json"
    keyfile.write_text(
        json.dumps(
            {
                full_entry["hash"]: {"name": full_entry["name"], "scope": "full"},
                audit_entry["hash"]: {"name": audit_entry["name"], "scope": "audit"},
            }
        )
    )
    monkeypatch.setenv("PV_API_KEYS_FILE", str(keyfile))

    import importlib

    import api.server as server

    importlib.reload(server)

    return server, full_entry["key"], audit_entry["key"]


def test_full_key_can_decide(tmp_path, monkeypatch):
    server, full_key, audit_key = _client_with_scoped_keys(tmp_path, monkeypatch)
    with TestClient(server.app) as c:
        r = c.post(
            "/v1/decide",
            json={
                "agent_id": "a1",
                "capability": "crm.read_contact",
                "timestamp": time.time(),
            },
            headers={"X-API-Key": full_key},
        )
        assert r.status_code in (200, 202, 403)  # any real verdict, not 401


def test_audit_key_rejected_on_decide(tmp_path, monkeypatch):
    """The core security property: an audit-scoped key must never be
    able to exercise enforcement authority."""
    server, full_key, audit_key = _client_with_scoped_keys(tmp_path, monkeypatch)
    with TestClient(server.app) as c:
        r = c.post(
            "/v1/decide",
            json={
                "agent_id": "a1",
                "capability": "crm.read_contact",
                "timestamp": time.time(),
            },
            headers={"X-API-Key": audit_key},
        )
        assert r.status_code == 401


def test_audit_key_can_verify(tmp_path, monkeypatch):
    server, full_key, audit_key = _client_with_scoped_keys(tmp_path, monkeypatch)
    with TestClient(server.app) as c:
        r = c.get("/v1/verify", headers={"X-API-Key": audit_key})
        assert r.status_code == 200


def test_audit_key_can_export(tmp_path, monkeypatch):
    server, full_key, audit_key = _client_with_scoped_keys(tmp_path, monkeypatch)
    with TestClient(server.app) as c:
        # produce at least one record with the full key first
        c.post(
            "/v1/decide",
            json={
                "agent_id": "a1",
                "capability": "crm.read_contact",
                "timestamp": time.time(),
            },
            headers={"X-API-Key": full_key},
        )

        r = c.get("/v1/audit/export", headers={"X-API-Key": audit_key})
        assert r.status_code == 200

        envelopes = c.get(
            "/v1/audit/envelopes",
            headers={"X-API-Key": audit_key},
        )
        assert envelopes.status_code == 200


def test_full_key_can_also_verify_and_export(tmp_path, monkeypatch):
    """Full scope satisfies audit requirements too -- an operator
    isn't locked out of their own audit endpoints."""
    server, full_key, audit_key = _client_with_scoped_keys(tmp_path, monkeypatch)
    with TestClient(server.app) as c:
        assert c.get("/v1/verify", headers={"X-API-Key": full_key}).status_code == 200
        assert (
            c.get("/v1/audit/export", headers={"X-API-Key": full_key}).status_code
            == 200
        )


def test_audit_key_rejected_on_outcome_and_other_enforcement_endpoints(
    tmp_path, monkeypatch
):
    server, full_key, audit_key = _client_with_scoped_keys(tmp_path, monkeypatch)
    with TestClient(server.app) as c:
        assert (
            c.post(
                "/v1/outcome",
                json={
                    "decision_id": "fake",
                    "status": "ok",
                },
                headers={"X-API-Key": audit_key},
            ).status_code
            == 401
        )

        assert c.get("/v1/blocked", headers={"X-API-Key": audit_key}).status_code == 401
        assert (
            c.get("/v1/divergent", headers={"X-API-Key": audit_key}).status_code == 401
        )


def test_no_key_still_rejected_on_audit_endpoints(tmp_path, monkeypatch):
    server, full_key, audit_key = _client_with_scoped_keys(tmp_path, monkeypatch)
    with TestClient(server.app) as c:
        assert c.get("/v1/verify").status_code == 401
        assert c.get("/v1/audit/export").status_code == 401
        assert c.get("/v1/audit/envelopes").status_code == 401
