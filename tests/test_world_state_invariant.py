"""Tests for World-State Behavioral Invariants."""

from agent_dna.multi_agent import (
    GraphBuilder,
    InteractionEvent,
    WorldStateInvariant,
)


def ev(exec_id, src, dst, t, state):
    return InteractionEvent(
        execution_id=exec_id,
        source=src,
        target=dst,
        timestamp=t,
        metadata={"state": state},
    )


def build(events):
    return GraphBuilder().ingest_many(events).build_all()[0]


def test_world_state_allows_valid_transition():
    train = [
        ev("t1", "planner", "risk", 1, "PO_CREATED"),
        ev("t1", "risk", "finance", 2, "RISK_APPROVED"),
        ev("t1", "finance", "payment", 3, "SETTLED"),
    ]

    inv = WorldStateInvariant()
    inv.learn([build(train)])

    result = inv.check(build(train))

    assert result.passed
    assert result.severity == 0.0
    assert not result.hard


def test_world_state_detects_invalid_transition():
    train = [
        ev("t1", "planner", "risk", 1, "PO_CREATED"),
        ev("t1", "risk", "finance", 2, "RISK_APPROVED"),
        ev("t1", "finance", "payment", 3, "SETTLED"),
    ]

    attack = [
        ev("x", "planner", "payment", 1, "PO_CREATED"),
        ev("x", "payment", "ledger", 2, "SETTLED"),
    ]

    inv = WorldStateInvariant()
    inv.learn([build(train)])

    result = inv.check(build(attack))

    assert not result.passed
    assert not result.hard
    assert result.severity > 0.0
    assert result.violations
