"""An unresolved role must never pass the authority invariant.

Regression for a fail-open at the runtime call site: AuthorityInvariant was
constructed with ignore_unknown=True, and check() skipped any role edge
containing "unknown". An agent whose role never resolved could therefore
drive a payment agent without breaching this invariant -- the exact case the
module docstring claims to stop.
"""

from __future__ import annotations

import pytest

from agent_dna.multi_agent.authority import AuthorityInvariant
from agent_dna.multi_agent.base import Verdict
from agent_dna.multi_agent.events import InteractionEvent
from agent_dna.multi_agent.interaction_graph import InteractionGraph
from agent_dna.multi_agent.runtime_validator import RuntimeValidator


def ev(exec_id, source, target, s_role, t_role, ts):
    return InteractionEvent(
        execution_id=exec_id,
        source=source,
        target=target,
        source_role=s_role,
        target_role=t_role,
        timestamp=ts,
    )


def _known_good():
    return [
        InteractionGraph("g1").extend(
            [
                ev("g1", "p", "r", "planner", "risk", 1.0),
                ev("g1", "r", "pay", "risk", "payment", 2.0),
            ]
        )
    ]


def test_unresolved_source_role_is_a_hard_breach():
    inv = AuthorityInvariant()
    inv.learn(_known_good())
    bad = InteractionGraph("b").add_event(
        ev("b", "ghost", "pay", "unknown", "payment", 1.0)
    )
    res = inv.check(bad)
    assert not res.passed
    assert res.hard
    assert any("UNRESOLVED_ACTOR_INFLUENCE" in v for v in res.violations)


def test_unresolved_target_role_escalates_but_does_not_block():
    """A known actor influencing a newly-seen agent is novelty, not an
    escalation attack. It fails the invariant (severity 1.0) but must not
    hard-block, or every new agent joining a swarm halts the system."""
    inv = AuthorityInvariant()
    inv.learn(_known_good())
    bad = InteractionGraph("b").add_event(
        ev("b", "r", "ghost", "risk", "unknown", 1.0)
    )
    res = inv.check(bad)
    assert not res.passed
    assert not res.hard
    assert 0.0 < res.severity < 1.0
    assert any("UNRESOLVED_TARGET_INFLUENCE" in v for v in res.violations)


def test_unresolved_edge_never_enters_the_allowlist():
    """Training must not sanction an edge it could not identify."""
    inv = AuthorityInvariant()
    inv.learn(
        [
            InteractionGraph("g1").extend(
                [
                    ev("g1", "p", "r", "planner", "risk", 1.0),
                    ev("g1", "ghost", "pay", "unknown", "payment", 2.0),
                ]
            )
        ]
    )
    assert ("unknown", "payment") not in inv.allowed_role_edges
    assert all("unknown" not in e for e in inv.allowed_role_edges)


def test_runtime_validator_blocks_unresolved_role_influence():
    """The fail-open lived at the runtime call site, so pin it there."""
    corpus = [
        ev("c1", "p", "r", "planner", "risk", 1.0),
        ev("c1", "r", "pay", "risk", "payment", 2.0),
    ]
    v = RuntimeValidator.from_corpus(corpus)
    breach = [
        ev("live", "p", "r", "planner", "risk", 1.0),
        ev("live", "r", "pay", "risk", "payment", 2.0),
        ev("live", "ghost", "pay", "unknown", "payment", 3.0),
    ]
    assert v.validate_events(breach).verdict is Verdict.BLOCK


def test_fail_open_flag_cannot_be_reintroduced():
    """ignore_unknown was the fail-open. Passing it must fail loudly."""
    with pytest.raises(TypeError):
        AuthorityInvariant(ignore_unknown=True)


def test_untrained_authority_invariant_abstains():
    """No learned role edges means roles are not in use in this deployment.
    Enforcing an authority model that was never trained blocks every
    execution regardless of behaviour."""
    inv = AuthorityInvariant()
    inv.learn([InteractionGraph("g1").add_event(ev("g1", "a", "b", "unknown", "unknown", 1.0))])
    assert not inv.trained
    res = inv.check(
        InteractionGraph("b").add_event(ev("b", "x", "y", "unknown", "unknown", 1.0))
    )
    assert res.passed
    assert not res.hard
    assert inv.describe()["role_model_trained"] is False


def test_trained_invariant_does_not_abstain_on_unresolved_actor():
    """Once roles are in use, an unresolved actor is meaningful again."""
    inv = AuthorityInvariant()
    inv.learn(_known_good())
    assert inv.trained
    res = inv.check(
        InteractionGraph("b").add_event(ev("b", "ghost", "pay", "unknown", "payment", 1.0))
    )
    assert not res.passed
    assert res.hard
