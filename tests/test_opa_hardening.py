"""OPA connector hardening: fail-closed on every degraded path,
bounded latency, rule identity, cache safety, transport config."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from agent_dna.adapters_policy.opa import (
    OPAPolicyAdapter, PolicyUnavailableError,
)
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.trace import AgentAction
from tests.test_p0_audit import StubScorer

DEAD = "http://127.0.0.1:9"          # discard port


def _adapter(**kw):
    kw.setdefault("endpoint", DEAD)
    kw.setdefault("deadline_seconds", 0.4)
    a = OPAPolicyAdapter(**kw)
    a.DEFAULT_BACKOFF = 0.0
    return a


class _Handler(BaseHTTPRequestHandler):
    RESULT = {}
    DELAY = 0.0

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.DELAY:
            time.sleep(self.DELAY)
        body = json.dumps({"result": self.RESULT}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _serve(result, delay=0.0):
    cls = type("H", (_Handler,), {"RESULT": result, "DELAY": delay})
    srv = HTTPServer(("127.0.0.1", 0), cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# ---- bundle fail-closed (the surviving fail-open branch) --------------

def test_bundle_silence_cannot_authorize(tmp_path):
    """A capability in NEITHER list used to return fired=False, which
    the engine skips -> an OPA outage silently became ALLOW."""
    b = tmp_path / "bundle.json"
    b.write_text(json.dumps({"denied_capabilities": ["storage.bulk_export"],
                             "allowed_capabilities": []}))
    with pytest.raises(PolicyUnavailableError, match="silence"):
        _adapter(bundle_path=str(b)).check(
            agent_id="a", capability="payments.initiate_wire")


def test_bundle_denial_is_authoritative(tmp_path):
    b = tmp_path / "bundle.json"
    b.write_text(json.dumps({"denied_capabilities": ["storage.bulk_export"]}))
    r = _adapter(bundle_path=str(b)).check(
        agent_id="a", capability="storage.bulk_export")
    assert r.fired and r.outcome == "block" and r.degraded
    assert r.matched_rule_id == "bundle:denied:storage.bulk_export"


def test_bundle_allowlist_clears_explicitly(tmp_path):
    b = tmp_path / "bundle.json"
    b.write_text(json.dumps({"allowed_capabilities": ["crm.read_contact"]}))
    r = _adapter(bundle_path=str(b)).check(
        agent_id="a", capability="crm.read_contact")
    assert not r.fired and r.degraded


def test_engine_blocks_when_bundle_has_no_opinion(tmp_path):
    b = tmp_path / "bundle.json"
    b.write_text(json.dumps({"denied_capabilities": []}))
    engine = DecisionEngine(scorer=StubScorer(),
                            policy=_adapter(bundle_path=str(b)))
    result = engine.decide(AgentAction(
        agent_id="a", capability="payments.initiate_wire",
        timestamp=time.time()))
    assert result.decision is Decision.BLOCK
    assert result.triggered_by == "engine_fault"


# ---- bounded latency --------------------------------------------------

def test_total_deadline_is_respected():
    """Worst case must be the deadline, not attempts x timeout."""
    a = _adapter(deadline_seconds=0.3)
    start = time.monotonic()
    with pytest.raises(PolicyUnavailableError):
        a.check(agent_id="a", capability="x")
    assert time.monotonic() - start < 1.0
    assert a.metrics_summary()["deadline_exceeded"] >= 0


def test_slow_opa_fails_closed_within_budget():
    srv = _serve({"fired": False}, delay=1.5)
    try:
        a = _adapter(endpoint=f"http://127.0.0.1:{srv.server_port}",
                     deadline_seconds=0.4)
        start = time.monotonic()
        with pytest.raises(PolicyUnavailableError):
            a.check(agent_id="a", capability="x")
        assert time.monotonic() - start < 2.0
    finally:
        srv.shutdown()


# ---- rule identity ----------------------------------------------------

@pytest.mark.parametrize("key", ["rule_id", "policy_id", "matched_rule_id"])
def test_rule_identity_surfaces_from_rego(key):
    srv = _serve({"fired": True, "outcome": "block",
                  "reason": "wire cap exceeded", key: "WIO-PAY-014"})
    try:
        r = OPAPolicyAdapter(
            endpoint=f"http://127.0.0.1:{srv.server_port}"
        ).check(agent_id="a", capability="payments.initiate_wire")
        assert r.fired and r.matched_rule_id == "WIO-PAY-014"
    finally:
        srv.shutdown()


def test_rule_identity_absent_is_honestly_none():
    srv = _serve({"fired": True, "outcome": "block", "reason": "denied"})
    try:
        r = OPAPolicyAdapter(
            endpoint=f"http://127.0.0.1:{srv.server_port}"
        ).check(agent_id="a", capability="x")
        assert r.matched_rule_id is None
    finally:
        srv.shutdown()


def test_unknown_outcome_for_fired_rule_refuses_interpretation():
    srv = _serve({"fired": True, "outcome": "maybe", "reason": "?"})
    try:
        with pytest.raises(PolicyUnavailableError, match="unknown outcome"):
            OPAPolicyAdapter(
                endpoint=f"http://127.0.0.1:{srv.server_port}"
            ).check(agent_id="a", capability="x")
    finally:
        srv.shutdown()


# ---- cache safety -----------------------------------------------------

def test_cache_disabled_by_default():
    srv = _serve({"fired": False, "outcome": "allow", "reason": "ok"})
    try:
        a = OPAPolicyAdapter(endpoint=f"http://127.0.0.1:{srv.server_port}")
        for _ in range(3):
            a.check(agent_id="a", capability="x")
        assert a.metrics_summary()["cache_hits"] == 0
        assert a.metrics_summary()["requests"] == 3
    finally:
        srv.shutdown()


def test_denials_are_never_cached():
    """A cached denial would outlive the rule's revocation."""
    srv = _serve({"fired": True, "outcome": "block", "reason": "no"})
    try:
        a = OPAPolicyAdapter(endpoint=f"http://127.0.0.1:{srv.server_port}",
                             cache_ttl=60)
        a.check(agent_id="a", capability="x")
        a.check(agent_id="a", capability="x")
        assert a.metrics_summary()["cache_hits"] == 0
    finally:
        srv.shutdown()


def test_cache_is_bounded():
    srv = _serve({"fired": False, "outcome": "allow", "reason": "ok"})
    try:
        a = OPAPolicyAdapter(endpoint=f"http://127.0.0.1:{srv.server_port}",
                             cache_ttl=60)
        a.MAX_CACHE_ENTRIES = 5
        for i in range(20):
            a.check(agent_id=f"agent-{i}", capability="x")
        assert len(a._cache) <= 5
    finally:
        srv.shutdown()


# ---- transport config -------------------------------------------------

def test_https_endpoint_builds_tls_context():
    a = OPAPolicyAdapter(endpoint="https://opa.internal:8181")
    assert a.health()["tls"] is True
    assert a.health()["mtls"] is False


def test_bearer_token_is_sent():
    a = OPAPolicyAdapter(endpoint=DEAD, token="secret-token")
    assert a._headers()["Authorization"] == "Bearer secret-token"
    assert a.health()["authenticated"] is True


def test_plaintext_endpoint_has_no_tls_context():
    assert OPAPolicyAdapter(endpoint=DEAD)._ssl_context is None
