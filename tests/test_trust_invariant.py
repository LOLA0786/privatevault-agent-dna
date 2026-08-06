"""Operational coverage for the trust invariant."""

import pytest

from agent_dna.multi_agent.base import Verdict
from agent_dna.multi_agent.events import InteractionEvent
from agent_dna.multi_agent.interaction_graph import InteractionGraph
from agent_dna.multi_agent.runtime_validator import RuntimeValidator
from agent_dna.multi_agent.trust import TrustInvariant


def _graph(execution_id: str, trust: float) -> InteractionGraph:
    return InteractionGraph(execution_id).add_event(
        InteractionEvent(
            execution_id=execution_id,
            source="agent-a",
            target="agent-b",
            timestamp=1.0,
            trust=trust,
        )
    )


def test_learns_trust_from_interaction_events():
    inv = TrustInvariant()
    inv.learn([_graph("train-1", 0.95), _graph("train-2", 0.85)])
    assert inv.minimum_trust == {("agent-a", "agent-b"): 0.85}


def test_review_on_material_trust_degradation():
    validator = RuntimeValidator.from_graphs([_graph("train", 0.90)])
    result = validator.validate(_graph("candidate", 0.75))
    assert result.verdict is Verdict.REVIEW
    assert any("trust degradation" in reason for reason in result.reasons)


def test_hard_block_on_severe_trust_degradation():
    validator = RuntimeValidator.from_graphs([_graph("train", 0.90)])
    result = validator.validate(_graph("candidate", 0.50))
    assert result.verdict is Verdict.BLOCK
    assert any("trust breach" in reason for reason in result.reasons)


def test_invalid_candidate_trust_fails_closed():
    inv = TrustInvariant()
    inv.learn([_graph("train", 0.90)])
    result = inv.check(_graph("candidate", 1.01))
    assert result.hard is True
    assert result.passed is False
    assert result.severity == 1.0


def test_invalid_training_trust_is_rejected():
    with pytest.raises(ValueError, match="invalid trust score"):
        TrustInvariant().learn([_graph("train", -0.01)])


@pytest.mark.parametrize(
    ("review_margin", "block_margin"),
    [(-0.1, 0.3), (0.4, 0.3), (0.1, 1.1)],
)
def test_invalid_threshold_configuration_is_rejected(
    review_margin: float, block_margin: float
):
    with pytest.raises(ValueError, match="trust margins"):
        TrustInvariant(review_margin, block_margin)
