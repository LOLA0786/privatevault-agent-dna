"""What the sequence signal means, pinned before anyone changes it.

ceil_surprise is computed AFTER fitting, so it is the surprise of the
most surprising transition the agent actually produced in training,
measured against its own fitted model. The scorer then reports excess
over that ceiling: anything inside the training envelope scores zero,
and only behaviour beyond everything seen produces a signal.

That is the right shape for an advisory layer that may escalate but
never approve -- it stays silent on normal behaviour rather than
crying wolf.

TRIPWIRE, NOT SPECIFICATION. The docstring in dynamics.py describes a
95th-percentile ceiling; the code uses max. That divergence is real and
unresolved. max is outlier-sensitive: one freak training transition
raises the ceiling and suppresses later signal. If the ceiling becomes
a quantile, test_the_most_surprising_training_transition_scores_zero
is the assertion that will move, and it should move deliberately.
"""

import time

import pytest

from agent_dna.adapters import synthetic_normal_trace
from agent_dna.dynamics import _START, BehaviorDynamics
from agent_dna.manifold import CapabilityManifold
from agent_dna.scorer import DriftScorer
from agent_dna.trace import AgentAction


@pytest.fixture
def trace():
    return synthetic_normal_trace(seed=11)


@pytest.fixture
def dynamics(trace):
    return BehaviorDynamics().fit([trace])


def _training_surprises(dynamics, trace):
    out = []
    prev = _START
    for cap in trace.capabilities:
        out.append(dynamics.surprise(prev, cap))
        prev = cap
    return out


def _scorer(trace):
    return DriftScorer(
        manifold=CapabilityManifold().fit([trace]),
        dynamics=BehaviorDynamics().fit([trace]),
    )


def _score(scorer, capability, prev=None):
    action = AgentAction(
        agent_id="sales-agent-01",
        capability=capability,
        timestamp=time.time(),
        arguments={},
    )
    return scorer.score(action, prev_capability=prev)


# --- the ceiling --------------------------------------------------------


def test_ceiling_is_the_maximum_training_surprise(dynamics, trace):
    """Not a quantile, whatever the docstring says. Pinned so the
    divergence is visible rather than discovered later."""
    assert dynamics.ceil_surprise == pytest.approx(
        max(_training_surprises(dynamics, trace))
    )


def test_ceiling_is_measured_against_the_fitted_model(dynamics, trace):
    """Computed after fit, so every training transition is one the model
    has already seen. The ceiling is therefore low in absolute terms --
    it is a reference point, not a danger threshold."""
    surprises = _training_surprises(dynamics, trace)
    assert dynamics.ceil_surprise >= max(surprises) - 1e-9
    assert dynamics.ceil_surprise > 0


def test_unfitted_dynamics_has_a_safe_default():
    assert BehaviorDynamics().ceil_surprise == 1.0


# --- excess over the envelope ------------------------------------------


def test_the_most_surprising_training_transition_scores_zero(dynamics, trace):
    """THE TRIPWIRE. Under max, the worst training transition sits exactly
    at the ceiling, so its excess is zero. Under a 95th-percentile
    ceiling it would not -- this assertion is what tells you the
    semantics moved."""
    surprises = _training_surprises(dynamics, trace)
    peak = max(surprises)
    excess = (peak - dynamics.ceil_surprise) / max(dynamics.ceil_surprise, 1.0)
    assert max(0.0, min(1.0, excess)) == 0.0


def test_a_novel_transition_scores_above_the_envelope(dynamics):
    """A capability never seen in training is more surprising than
    anything that was, so it clears the ceiling."""
    novel = dynamics.surprise("<never-seen-prefix>", "<never-seen-capability>")
    assert novel > dynamics.ceil_surprise


def test_excess_is_monotonic_in_surprise(dynamics):
    ceiling = dynamics.ceil_surprise

    def excess(surprise):
        return max(0.0, min(1.0, (surprise - ceiling) / max(ceiling, 1.0)))

    assert excess(ceiling) == 0.0
    assert excess(ceiling * 1.5) > 0.0
    assert excess(ceiling * 3) > excess(ceiling * 1.5)
    assert excess(ceiling * 1000) == 1.0


# --- the layer's contract ----------------------------------------------


def test_a_training_transition_produces_no_sequence_signal(trace):
    """Reaches into _sequence deliberately. score() blends this with
    novelty, arguments and rate, so the composite cannot isolate the
    quantity under test -- and it is the quantity, not the blend, whose
    semantics this file exists to pin."""
    scorer = _scorer(trace)
    caps = trace.capabilities
    action = AgentAction(
        agent_id="sales-agent-01",
        capability=caps[1],
        timestamp=time.time(),
        arguments={},
    )
    assert scorer._sequence(action, caps[0], []) == 0.0
