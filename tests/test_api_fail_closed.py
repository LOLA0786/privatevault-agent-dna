"""API-level fail-closed: a fault inside the decision engine, hit
through the real HTTP path, must return 403 with an auditable fault
record — never a 500, never a silent 200."""

import time

from fastapi.testclient import TestClient


def _client(tmp_path, monkeypatch):
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "fc.db"))
    monkeypatch.delenv("PV_API_KEYS_FILE", raising=False)
    monkeypatch.delenv("PV_RECEIPT_SIGNING_KEY", raising=False)
    import importlib
    import api.server as server
    importlib.reload(server)
    return server


def test_faulting_scorer_returns_403_not_500(tmp_path, monkeypatch):
    server = _client(tmp_path, monkeypatch)

    class RaisingScorer:
        def score(self, action, prev_capability=None):
            raise RuntimeError("scorer blew up in production")

    with TestClient(server.app) as c:
        # swap the live engine's scorer post-startup to simulate a
        # runtime fault in a dependency (e.g. a flaky evidence source)
        server.state["engine"].scorer = RaisingScorer()

        r = c.post("/v1/decide", json={
            "agent_id": "fault-agent",
            "capability": "crm.read_contact",
            "timestamp": time.time(),
        })

        assert r.status_code == 403, (
            f"fault propagated as {r.status_code}, not fail-closed 403"
        )
        body = r.json()
        assert body["decision"] == "block"
        assert body["triggered_by"] == "engine_fault"
        assert "scorer blew up" in body["reason"]

        # the fault record itself must be a valid, sealed, queryable
        # record — not a special case that skips the audit trail
        rec = body["record"]
        assert rec["record_hash"]
        assert rec["decision"] == "block"

        v = c.get("/v1/verify")
        assert v.json()["chains"]["fault-agent"] is True


def test_faulting_uaal_checker_returns_403(tmp_path, monkeypatch):
    server = _client(tmp_path, monkeypatch)

    class RaisingUAAL:
        def check(self, action, evidence):
            raise TypeError("evidence source unreachable")

    with TestClient(server.app) as c:
        server.state["engine"].uaal = RaisingUAAL()

        r = c.post("/v1/decide", json={
            "agent_id": "fault-agent-2",
            "capability": "payment.pay_invoice",
            "timestamp": time.time(),
            "evidence": {"enterprise_state": {}},
        })

        assert r.status_code == 403
        assert r.json()["triggered_by"] == "engine_fault"
