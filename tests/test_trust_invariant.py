"""TrustInvariant is NOT WIRED (documented, pinned state).

Reproduced from an external release audit. TrustInvariant iterates
graph.edges expecting edge OBJECTS with .source / .target /
.trust_score, but InteractionGraph.edges is a set[tuple[str, str]] --
(source, target) agent-id pairs with no per-edge trust. So it cannot
operate on a real graph, and nothing in the serving path calls it.
The project's trust data is per-AGENT (consensus.TrustRegistry), not
per-EDGE; a correct wiring needs a modelling decision that is deferred,
not guessed. This test pins the not-wired state so the gap is visible
and regression-locked -- if it ever STOPS raising, trust-weighted
edges have been built and this should be replaced with real coverage.
"""

import pytest

from agent_dna.multi_agent.trust import TrustInvariant


class _TupleEdgeGraph:
    """Minimal stand-in exposing edges exactly as InteractionGraph does:
    a set of (source, target) string tuples. TrustInvariant treats each
    edge as an object (edge.source, edge.trust_score), so this must
    raise."""
    edges = {("agent-a", "agent-b"), ("agent-b", "agent-c")}


def test_fit_cannot_operate_on_the_real_edge_model():
    with pytest.raises((AttributeError, TypeError)):
        TrustInvariant().fit([_TupleEdgeGraph()])


def test_validate_cannot_operate_on_the_real_edge_model():
    inv = TrustInvariant()
    inv.minimum_trust = {("agent-a", "agent-b"): 0.9}  # pretend fit ran
    with pytest.raises((AttributeError, TypeError)):
        inv.validate(_TupleEdgeGraph())


def test_docstring_marks_it_not_wired():
    assert "NOT WIRED" in (TrustInvariant.__doc__ or ""), \
        "the not-wired status must stay documented on the class"
