"""
TUE-05 circuit breaker — each test exercises the actual failure mode:
  1. runaway loop        (rate trip)
  2. salami drain        (per-action passes, aggregate trips)
  3. refusal thrash      (probing agent)
  4. restart persistence (trip survives a new process/instance)
  5. reset authorization (unauthorized rejected, authorized chained)
"""

import pytest

from agent_dna.circuit_breaker import (
    RESET_CAPABILITY,
    BreakerConfig,
    CircuitBreaker,
    GuardedEngine,
)
from agent_dna.decision import Decision, DecisionResult, Severity


class FakeClock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t

    def tick(self, dt: float) -> None:
        self.t += dt


class FakeAction:
    def __init__(self, agent_id="agent-1", capability="payments.transfer", amount=None):
        self.agent_id = agent_id
        self.capability = capability
        if amount is not None:
            self.amount = amount


class FakeEngine:
    """Stands in for DecisionEngine; returns a canned verdict."""

    def __init__(self, decision=Decision.ALLOW):
        self.decision = decision
        self.calls = 0

    def decide(self, action, prev_capability=None, evidence=None):
        self.calls += 1
        return DecisionResult(
            decision=self.decision,
            triggered_by="baseline",
            reason="fake",
            capability=action.capability,
            agent_id=action.agent_id,
            drift_score=0.0,
            severity=list(Severity)[0],
        )


@pytest.fixture
def db(tmp_path):
    return tmp_path / "breaker.db"


def test_runaway_loop_rate_trip(db):
    clock = FakeClock()
    br = CircuitBreaker(
        db,
        BreakerConfig(
            max_decisions=50, window_seconds=10.0, max_consecutive_refusals=None
        ),
        clock=clock,
    )
    guarded = GuardedEngine(FakeEngine(), br)
    a = FakeAction()

    tripped_at = None
    for i in range(100):
        clock.tick(0.05)  # 100 calls in 5s
        r = guarded.decide(a)
        if r.triggered_by == "circuit_breaker":
            tripped_at = i
            break

    assert tripped_at is not None, "runaway loop never tripped the breaker"
    assert tripped_at <= 52
    r = guarded.decide(a)
    assert r.decision is Decision.BLOCK
    assert r.triggered_by == "circuit_breaker"
    assert "rate_trip" in r.reason


def test_salami_drain_volume_trip(db):
    clock = FakeClock()
    br = CircuitBreaker(
        db,
        BreakerConfig(
            max_decisions=None,
            window_seconds=60.0,
            max_cumulative_amount=1000.0,
            max_consecutive_refusals=None,
        ),
        clock=clock,
    )
    engine = FakeEngine(Decision.ALLOW)  # each action individually fine
    guarded = GuardedEngine(engine, br)

    blocked = None
    for i in range(20):
        clock.tick(1.0)
        r = guarded.decide(FakeAction(amount=60.0))  # 60 << per-action caps
        if r.triggered_by == "circuit_breaker":
            blocked = i
            break

    # 17 * 60 = 1020 > 1000 -> trips on observe after 17th, blocks 18th call
    assert blocked is not None, "salami drain never tripped the breaker"
    assert "volume_trip" in guarded.decide(FakeAction(amount=60.0)).reason
    assert engine.calls <= 18  # engine never saw the drained tail


def test_refusal_thrash_trip(db):
    clock = FakeClock()
    br = CircuitBreaker(
        db,
        BreakerConfig(max_decisions=None, max_consecutive_refusals=5),
        clock=clock,
    )
    guarded = GuardedEngine(FakeEngine(Decision.BLOCK), br)
    a = FakeAction()

    for _ in range(5):
        clock.tick(1.0)
        guarded.decide(a)

    r = guarded.decide(a)
    assert r.decision is Decision.BLOCK
    assert r.triggered_by == "circuit_breaker"
    assert "refusal_thrash" in r.reason


def test_trip_survives_restart(db):
    clock = FakeClock()
    br1 = CircuitBreaker(
        db,
        BreakerConfig(max_decisions=None, max_consecutive_refusals=3),
        clock=clock,
    )
    for _ in range(3):
        clock.tick(1.0)
        br1.observe("agent-1", "block")
    assert br1.is_tripped("agent-1")
    br1.close()

    # new instance on the same path == new process after restart
    br2 = CircuitBreaker(db, BreakerConfig(), clock=clock)
    assert br2.is_tripped("agent-1"), "restart cleared the trip (evasion)"
    r = GuardedEngine(FakeEngine(), br2).decide(FakeAction())
    assert r.decision is Decision.BLOCK
    assert r.triggered_by == "circuit_breaker"


def test_reset_capability_gated_and_chained(db):
    clock = FakeClock()
    br = CircuitBreaker(
        db,
        BreakerConfig(max_decisions=None, max_consecutive_refusals=3),
        clock=clock,
    )
    for _ in range(3):
        clock.tick(1.0)
        br.observe("agent-1", "block")
    assert br.is_tripped("agent-1")

    grants = {("ciso-1", RESET_CAPABILITY)}

    def authorize(actor, cap):
        return (actor, cap) in grants

    with pytest.raises(PermissionError):
        br.reset("agent-1", actor_id="intern-7", authorize=authorize)
    assert br.is_tripped("agent-1"), "unauthorized reset cleared the trip"

    record = br.reset("agent-1", actor_id="ciso-1", authorize=authorize)
    assert not br.is_tripped("agent-1")
    assert record["actor"] == "ciso-1"
    assert record["prev_hash"] != "0" * 64  # chained onto the trip record
    assert br.verify_log(), "trip/reset chain does not verify"
