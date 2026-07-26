"""No decision may leave a reservation stranded in the breaker ledger.

GuardedEngine.reserve() writes a row with decision='reserved' BEFORE the
engine runs, so that concurrent callers serialize against the same
remaining budget. finalize() converts that row to the real verdict.

Rate and cumulative-amount checks count every row in the window
regardless of state, so a stranded reservation does not distort the
budget. The refusal-thrash check is different: it reads
`WHERE decision != 'reserved'`. A reservation that is never finalized is
therefore invisible to it, and a sustained fault produces an unbroken
run of refusals that the one detector built to escalate them cannot
see.

The grant_spend_fault path did exactly this: it returned _blocked(...)
directly, bypassing finalize. It was invisible because the window is
time-based, so the leak ages out on its own.
"""

from __future__ import annotations

import sqlite3

from agent_dna.advisory import Severity
from agent_dna.circuit_breaker import (
    BreakerConfig,
    CircuitBreaker,
    GuardedEngine,
)
from agent_dna.decision import Decision, DecisionResult
from agent_dna.trace import AgentAction


class _AllowingEngine:
    """Minimal engine: always ALLOW, always under a grant, so the
    record_spend path is reached."""

    def __init__(self, authorizer=None) -> None:
        self.authorizer = authorizer

    def decide(self, action, prev_capability=None, evidence=None):
        result = DecisionResult(
            decision=Decision.ALLOW,
            triggered_by="baseline",
            reason="ok",
            capability=action.capability,
            agent_id=action.agent_id,
            drift_score=0.0,
            severity=Severity.INFO,
        )
        result.grant_id = "grant-1"
        return result


class _FaultingAuthorizer:
    def record_spend(self, grant_id, amount):
        raise RuntimeError("grant ledger unavailable")


class _WorkingAuthorizer:
    def __init__(self) -> None:
        self.spends: list[tuple[str, float]] = []

    def record_spend(self, grant_id, amount):
        self.spends.append((grant_id, amount))


def _breaker(tmp_path, **cfg):
    return CircuitBreaker(
        tmp_path / "breaker.db",
        BreakerConfig(
            max_decisions=cfg.get("max_decisions"),
            window_seconds=cfg.get("window_seconds", 60.0),
            max_cumulative_amount=cfg.get("max_cumulative_amount"),
            max_consecutive_refusals=cfg.get("max_consecutive_refusals"),
        ),
    )


def _action(agent_id="a1", amount=100.0, i=0):
    return AgentAction(
        agent_id=agent_id,
        capability="payments.wire_transfer",
        timestamp=1751700000.0 + i,
        arguments={"amount": amount},
    )


def _reserved_rows(path) -> int:
    conn = sqlite3.connect(path)
    try:
        return conn.execute(
            "SELECT COUNT(*) FROM breaker_events WHERE decision = 'reserved'"
        ).fetchone()[0]
    finally:
        conn.close()


def test_reservation_is_finalized_on_the_happy_path(tmp_path) -> None:
    breaker = _breaker(tmp_path)
    guarded = GuardedEngine(_AllowingEngine(_WorkingAuthorizer()), breaker)

    guarded.decide(_action())

    assert _reserved_rows(tmp_path / "breaker.db") == 0


def test_reservation_is_finalized_when_grant_spend_faults(tmp_path) -> None:
    """The regression. A faulting grant ledger must still close out its
    reservation -- the action was refused, and a refusal is a verdict."""
    breaker = _breaker(tmp_path)
    guarded = GuardedEngine(_AllowingEngine(_FaultingAuthorizer()), breaker)

    result = guarded.decide(_action())

    assert result.decision is Decision.BLOCK
    assert "grant_spend_fault" in result.reason
    assert _reserved_rows(tmp_path / "breaker.db") == 0, (
        "the faulting path left a reservation stranded; it is invisible "
        "to the refusal-thrash detector for the rest of the window"
    )


def test_stranded_reservations_blind_the_refusal_thrash_detector(
    tmp_path,
) -> None:
    """The actual consequence, and it is not a budget problem.

    _evaluate's rate and cumulative-amount checks count every row in the
    window regardless of state, so a stranded reservation still consumes
    budget correctly. What it does NOT do is register as a refusal --
    the thrash query is explicitly `WHERE decision != 'reserved'`.

    So a sustained fault (broken grant ledger, every action refused)
    produced an unbroken stream of BLOCKs that the refusal-thrash
    detector could not see. The one escalation path built to notice
    "this agent keeps getting refused" was silently disabled for exactly
    the refusals that most needed escalating.

    With max_consecutive_refusals=3, three faulted actions must suspend
    the agent.
    """
    breaker = _breaker(tmp_path, max_consecutive_refusals=3)
    guarded = GuardedEngine(_AllowingEngine(_FaultingAuthorizer()), breaker)

    for i in range(6):
        result = guarded.decide(_action(amount=100.0, i=i))
        assert result.decision is Decision.BLOCK

    assert breaker.is_tripped("a1"), (
        "six consecutive refusals did not trip refusal_thrash (k=3): the "
        "refusals were recorded as 'reserved' and the detector skipped them"
    )

    conn = sqlite3.connect(tmp_path / "breaker.db")
    try:
        visible = conn.execute(
            "SELECT COUNT(*) FROM breaker_events WHERE decision != 'reserved'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert visible >= 3, (
        f"only {visible} refusals were visible to the thrash detector"
    )


def test_finalize_failure_does_not_change_the_verdict(tmp_path) -> None:
    """finalize() is bookkeeping. If it fails, the enforcement decision
    that was already made must stand unaltered."""
    breaker = _breaker(tmp_path)
    guarded = GuardedEngine(_AllowingEngine(_WorkingAuthorizer()), breaker)

    def boom(*_args, **_kwargs):
        raise RuntimeError("ledger write failed")

    breaker.finalize = boom  # type: ignore[method-assign]
    result = guarded.decide(_action())

    assert result.decision is Decision.ALLOW
    assert result.triggered_by == "baseline"
