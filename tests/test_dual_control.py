"""Definitional dual-control invariant — no corpus required."""

from agent_dna.multi_agent import (
    DualControlInvariant,
    InteractionEvent,
    InteractionGraph,
)
from agent_dna.multi_agent.runtime_validator import definitional_engine


def _ev(execution_id, source, intent, approval=False):
    return InteractionEvent(
        execution_id=execution_id,
        source=source,
        target="payment_rail",
        source_role="maker",
        target_role="rail",
        timestamp=1.0,
        intent=intent,
        approval=approval,
    )


def test_dual_control_blocks_same_agent_initiate_and_approve():
    graph = InteractionGraph("e1").extend(
        [
            _ev("e1", "maker-1", "payments.initiate_wire"),
            _ev("e1", "maker-1", "payments.approve_wire", approval=True),
        ]
    )
    result = DualControlInvariant().check(graph)
    assert not result.passed
    assert result.hard
    assert "maker==checker" in result.violations[0]


def test_dual_control_allows_distinct_maker_and_checker():
    graph = InteractionGraph("e1").extend(
        [
            _ev("e1", "maker-1", "payments.initiate_wire"),
            _ev("e1", "checker-1", "payments.approve_wire", approval=True),
        ]
    )
    assert DualControlInvariant().check(graph).passed


def test_definitional_engine_ready_without_corpus():
    engine = definitional_engine()
    graph = InteractionGraph("e1").extend(
        [
            _ev("e1", "maker-1", "payments.initiate_wire"),
            _ev("e1", "maker-1", "payments.approve_wire"),
        ]
    )
    verdict = engine.evaluate(graph)
    assert verdict.verdict.value == "BLOCK"
