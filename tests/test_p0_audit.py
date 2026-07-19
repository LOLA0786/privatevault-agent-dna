"""P0 audit findings -- failing contract tests (Commit set 1).

Each test asserts the CORRECT behavior for a finding from the
2026-07 external audit, and is marked xfail(strict=True): today the
suite reports them as expected failures (green); the moment a fix
lands, strict mode fails the suite until the marker is removed in the
SAME commit as the fix. No production code is modified in this batch.

Findings covered (audit numbering):
  P0-1  OPA "fail-closed" fallback actually allows
  P0-2  API key not bound to agent_id (impersonation)
  P0-4  independent verifier lineage gaps
  P0-5  circuit breaker trips after the crossing action
  P0-6  quorum counts one agent multiple times / vote replay
  P0-7  UAAL turns malformed or incomplete evidence into a pass
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.decision_record import DecisionRecord
from agent_dna.trace import AgentAction

ROOT = Path(__file__).resolve().parents[1]
GENESIS = "0" * 64


class StubScorer:
    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id, capability=action.capability,
            drift_score=0.0, severity=Severity.INFO, reasons=[],
        )


def _act(agent_id="a1", capability="crm.read_contact", arguments=None):
    return AgentAction(
        agent_id=agent_id, capability=capability,
        timestamp=time.time(), arguments=arguments or {},
    )


def _record(decision_id, agent_id="agent-x", parent=None,
            prev_hash=GENESIS, capability="crm.read_contact"):
    return DecisionRecord(
        decision_id=decision_id,
        parent_decision=parent,
        agent_id=agent_id,
        capability=capability,
        decision="allow",
        triggered_by="baseline",
        reason="",
        severity="none",
        drift_score=0.0,
        evidence=[],
        evidence_strength=0.0,
        arguments_digest="",
        outcome="pending",
        prev_hash=prev_hash,
    ).seal()


def _run_verifier(path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(ROOT / "tools" / "verify_records.py"), str(path)],
        capture_output=True, text=True,
    )


# =====================================================================
# P0-1  OPA fail-closed
# =====================================================================

def _dead_opa():
    from agent_dna.adapters_policy.opa import OPAPolicyAdapter
    a = OPAPolicyAdapter(endpoint="http://127.0.0.1:9",  # discard port
                         default_decision="block")
    a.DEFAULT_RETRY_COUNT = 1     # instance attrs shadow class constants
    a.DEFAULT_BACKOFF = 0.0
    a.DEFAULT_TIMEOUT = 0.2
    return a


def test_opa_unavailable_engine_blocks():
    engine = DecisionEngine(scorer=StubScorer(), policy=_dead_opa())
    result = engine.decide(_act())
    assert result.decision is Decision.BLOCK
    assert result.triggered_by == "engine_fault", (
        "an OPA outage must audit as an infrastructure fault, not as "
        f"a policy verdict (got {result.triggered_by!r})"
    )
    assert "opa" in result.reason.lower()


def test_opa_unavailable_adapter_contract():
    from agent_dna.adapters_policy.opa import PolicyUnavailableError
    with pytest.raises(PolicyUnavailableError):
        _dead_opa().check(agent_id="a1", capability="payments.wire")


class _EmptyOPAHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        body = json.dumps({"result": {}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # silence test output
        pass


def test_opa_empty_result_is_not_allow():
    from agent_dna.adapters_policy.opa import OPAPolicyAdapter
    srv = HTTPServer(("127.0.0.1", 0), _EmptyOPAHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        a = OPAPolicyAdapter(
            endpoint=f"http://127.0.0.1:{srv.server_port}",
            default_decision="block",
        )
        a.DEFAULT_RETRY_COUNT = 1
        a.DEFAULT_BACKOFF = 0.0
        from agent_dna.adapters_policy.opa import PolicyUnavailableError
        with pytest.raises(PolicyUnavailableError):
            a.check(agent_id="a1", capability="payments.wire")
    finally:
        srv.shutdown()


# =====================================================================
# P0-2  API identity binding
# =====================================================================

def _api_client(tmp_path, monkeypatch, key_names=("agent-a", "agent-b")):
    """Two full-scope keys named after the agents they should be bound
    to (identity-from-credential, the ConnectorMiddleware convention)."""
    from agent_dna.apikeys import generate_key

    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "p0.db"))
    entries = {}
    keys = {}
    for name in key_names:
        e = generate_key(name)
        entries[e["hash"]] = name
        keys[name] = e["key"]
    kf = tmp_path / "keys.json"
    kf.write_text(json.dumps(entries))
    monkeypatch.setenv("PV_API_KEYS_FILE", str(kf))

    import importlib
    import api.server as server
    importlib.reload(server)
    from fastapi.testclient import TestClient
    return TestClient(server.app), keys


def test_key_cannot_decide_as_another_agent(tmp_path, monkeypatch):
    client, keys = _api_client(tmp_path, monkeypatch)
    with client as c:
        r = c.post(
            "/v1/decide",
            headers={"X-API-Key": keys["agent-a"]},
            json={
                "agent_id": "agent-b",          # NOT the authenticated identity
                "capability": "crm.read_contact",
                "timestamp": time.time(),
            },
        )
        assert r.status_code in (403, 409, 422), (
            f"credential for agent-a decided as agent-b: {r.status_code}"
        )


def test_key_cannot_report_outcome_for_another_agent(tmp_path, monkeypatch):
    client, keys = _api_client(tmp_path, monkeypatch)
    with client as c:
        r = c.post(
            "/v1/decide",
            headers={"X-API-Key": keys["agent-a"]},
            json={
                "agent_id": "agent-a",
                "capability": "crm.read_contact",
                "timestamp": time.time(),
            },
        )
        assert r.status_code == 200
        decision_id = r.json()["record"]["decision_id"]

        r2 = c.post(
            "/v1/outcome",
            headers={"X-API-Key": keys["agent-b"]},   # different identity
            json={"decision_id": decision_id, "status": "ok",
                  "detail": "cross-agent report"},
        )
        assert r2.status_code in (403, 404, 409), (
            f"agent-b reported an outcome on agent-a's decision: "
            f"{r2.status_code}"
        )


# =====================================================================
# P0-4  independent verifier lineage
# =====================================================================

def test_verifier_rejects_nonexistent_parent(tmp_path):
    r1 = _record("d-1")
    r2 = _record("d-2", parent="ghost-decision-id",
                 prev_hash=r1.record_hash)
    f = tmp_path / "false_parent.jsonl"
    f.write_text(
        json.dumps(r1.to_dict()) + "\n" + json.dumps(r2.to_dict()) + "\n"
    )
    proc = _run_verifier(f)
    assert "PASS" not in proc.stdout, (
        "fabricated parent_decision verified clean:\n" + proc.stdout
    )


def test_verifier_rejects_duplicate_decision_id(tmp_path):
    r1 = _record("d-dup")
    r2 = _record("d-dup", prev_hash=r1.record_hash)   # same id, chained
    f = tmp_path / "dup_id.jsonl"
    f.write_text(
        json.dumps(r1.to_dict()) + "\n" + json.dumps(r2.to_dict()) + "\n"
    )
    proc = _run_verifier(f)
    assert "PASS" not in proc.stdout, (
        "duplicate decision_id verified clean:\n" + proc.stdout
    )


def test_anchor_verdict_is_consistent_between_verifiers(tmp_path):
    from agent_dna.decision_graph import DecisionGraph

    anchor = "ab" * 32                       # non-genesis provenance anchor
    r1 = _record("d-anchored", prev_hash=anchor)

    graph = DecisionGraph().add(r1)
    graph_ok = graph.verify_chain(r1.agent_id)

    f = tmp_path / "anchored.jsonl"
    f.write_text(json.dumps(r1.to_dict()) + "\n")
    verifier_ok = "PASS" in _run_verifier(f).stdout

    assert graph_ok == verifier_ok, (
        f"graph says {graph_ok}, public verifier says {verifier_ok} "
        "for the identical anchored chain"
    )


# =====================================================================
# P0-5  circuit breaker preflight
# =====================================================================

def _breaker(db, cap=100.0):
    from agent_dna.circuit_breaker import BreakerConfig, CircuitBreaker
    return CircuitBreaker(
        db,
        BreakerConfig(max_decisions=None, window_seconds=60.0,
                      max_cumulative_amount=cap,
                      max_consecutive_refusals=None),
    )


class _AllowEngine:
    def decide(self, action, prev_capability=None, evidence=None):
        from agent_dna.decision import DecisionResult, Severity as Sev
        return DecisionResult(
            decision=Decision.ALLOW, triggered_by="baseline",
            reason="stub", capability=action.capability,
            agent_id=action.agent_id, drift_score=0.0,
            severity=list(Sev)[0],
        )


class _Payment:
    def __init__(self, amount=None, arguments=None):
        self.agent_id = "spender-1"
        self.capability = "payments.transfer"
        if amount is not None:
            self.amount = amount
        if arguments is not None:
            self.arguments = arguments


@pytest.mark.xfail(
    strict=True,
    reason="P0-5: breaker observes AFTER the inner decision -- the "
           "payment that crosses the cap is still returned ALLOW; only "
           "the next one blocks",
)
def test_threshold_crossing_payment_blocked_before_execution(tmp_path):
    from agent_dna.circuit_breaker import GuardedEngine
    guarded = GuardedEngine(_AllowEngine(), _breaker(tmp_path / "b.db"))

    first = guarded.decide(_Payment(amount=60.0))
    assert first.decision is Decision.ALLOW          # 60 <= 100, fine

    second = guarded.decide(_Payment(amount=60.0))   # projects to 120
    assert second.decision is Decision.BLOCK, (
        "the cap-crossing payment itself was allowed "
        f"(got {second.decision}); a post-hoc trip is not a spending cap"
    )


@pytest.mark.xfail(
    strict=True,
    reason="P0-5: _default_amount reads action.amount and "
           "evidence['amount'] but never action.arguments['amount'] -- "
           "the normal AgentAction shape never trips the breaker",
)
def test_arguments_amount_reaches_breaker(tmp_path):
    from agent_dna.circuit_breaker import GuardedEngine
    guarded = GuardedEngine(_AllowEngine(), _breaker(tmp_path / "b2.db"))

    tripped = False
    for _ in range(5):                                # 5 x 60 = 300 >> 100
        r = guarded.decide(_Payment(arguments={"amount": 60.0}))
        if r.decision is Decision.BLOCK:
            tripped = True
            break
    assert tripped, (
        "300 spent via arguments['amount'] against a 100 cap and the "
        "breaker never saw a single rupee"
    )


# =====================================================================
# P0-6  quorum dedup + replay
# =====================================================================

def test_one_voter_cannot_vote_twice():
    from agent_dna.consensus.secure_quorum import SecureQuorum, TrustRegistry
    from agent_dna.consensus.signing import cast_vote, register_key

    tr = TrustRegistry()
    tr.set_score("solo", 0.3)
    register_key("solo", "secret-solo")
    q = SecureQuorum(threshold=0.67, trust_registry=tr)

    v = cast_vote("solo", "action-1", "APPROVE", "h-1")
    for _ in range(3):                                 # same vote, thrice
        q.submit("action-1", v)

    assert not q.check_quorum("action-1"), (
        "one agent with trust 0.3 achieved a 0.67 quorum by voting 3x"
    )


def test_vote_cannot_replay_across_actions():
    from agent_dna.consensus.secure_quorum import SecureQuorum, TrustRegistry
    from agent_dna.consensus.signing import cast_vote, register_key

    tr = TrustRegistry()
    tr.set_score("honest", 1.0)
    register_key("honest", "secret-honest")
    q = SecureQuorum(threshold=0.5, trust_registry=tr)

    v = cast_vote("honest", "action-1", "APPROVE", "shared-hash")
    q.submit("action-1", v)
    assert q.check_quorum("action-1")                  # legitimate

    # attacker replays the captured vote into a DIFFERENT action
    q.submit("action-2", v)
    assert not q.check_quorum("action-2"), (
        "a vote cast for action-1 was replayed to approve action-2"
    )


# =====================================================================
# P0-7  UAAL evidence honesty
# =====================================================================

def test_malformed_amount_fails_closed():
    from agent_dna.uaal_layer import UAALConstraintChecker

    res = UAALConstraintChecker().check(
        _act(capability="payments.pay_invoice",
             arguments={"amount": "not-a-number"}),
        evidence={"enterprise_state": {"invoice_amount": 100}},
    )
    assert res.violated or "monetary_conservation" not in [
        d["name"] for d in res.detail if d["passed"]
    ], (
        "amount='not-a-number' against a 100 invoice was reported as "
        f"conserved: violated={res.violated}, detail={res.detail}"
    )


def test_empty_enterprise_state_is_not_verified_state():
    from agent_dna.uaal_layer import UAALConstraintChecker

    res = UAALConstraintChecker().check(
        _act(capability="payments.pay_invoice",
             arguments={"amount": 999}),
        evidence={"enterprise_state": {}},             # key present, empty
    )
    state_passed = any(
        d["name"] == "enterprise_state" and d["passed"] for d in res.detail
    )
    assert res.violated or "enterprise_state" in res.checks_skipped or (
        not state_passed
    ), (
        "an empty enterprise_state was evaluated as a VALID verified "
        f"state: detail={res.detail}"
    )
