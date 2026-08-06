"""Tests for Cross-Agent Behavioral Invariants (Phase 1)."""

from __future__ import annotations

import pytest

from agent_dna.multi_agent import (
    AuthorityInvariant,
    GraphBuilder,
    InteractionEvent,
    InteractionGraph,
    InvariantEngine,
    RuntimeValidator,
    TemporalInvariant,
    TopologyInvariant,
    Verdict,
)

ROLE_OF = {
    "planner": "planning",
    "risk": "risk",
    "finance": "finance",
    "approval": "approval",
    "payment": "payment",
}
CHAIN = ["planner", "risk", "finance", "approval", "payment"]


def ev(exec_id, src, dst, t):
    return InteractionEvent(
        execution_id=exec_id,
        source=src,
        target=dst,
        timestamp=t,
        source_role=ROLE_OF.get(src, "unknown"),
        target_role=ROLE_OF.get(dst, "unknown"),
    )


def good(exec_id):
    return [
        ev(exec_id, s, d, i + 1.0)
        for i, (s, d) in enumerate(zip(CHAIN, CHAIN[1:], strict=False))
    ]


@pytest.fixture
def corpus():
    out = []
    for i in range(50):
        out.extend(good(f"t-{i}"))
    return out


@pytest.fixture
def graphs(corpus):
    return GraphBuilder().ingest_many(corpus).build_all()


# ---- graph construction ---------------------------------------------------
def test_graph_builder_groups_by_execution(corpus):
    builder = GraphBuilder().ingest_many(corpus)
    graphs = builder.build_all()
    assert len(graphs) == 50
    assert all(len(g) == 4 for g in graphs)


def test_graph_edges_and_roles():
    g = InteractionGraph("x").extend(good("x"))
    assert ("planner", "risk") in g.edges
    assert ("approval", "payment") in g.role_edges
    assert g.role_of("finance") == "finance"


def test_role_first_seen_ordering():
    g = InteractionGraph("x").extend(good("x"))
    assert g.role_precedes("finance", "payment") is True
    assert g.role_precedes("payment", "finance") is False
    assert g.role_precedes("finance", "ghost") is None


def test_event_execution_id_mismatch_raises():
    g = InteractionGraph("a")
    with pytest.raises(ValueError):
        g.add_event(ev("b", "planner", "risk", 1.0))


# ---- topology -------------------------------------------------------------
def test_topology_learns_allowed_and_mandatory(graphs):
    inv = TopologyInvariant()
    inv.learn(graphs)
    assert ("planner", "risk") in inv.allowed_edges
    assert ("finance", "approval") in inv.mandatory_edges


def test_topology_flags_novel_edge(graphs):
    inv = TopologyInvariant()
    inv.learn(graphs)
    bad = InteractionGraph("b").add_event(ev("b", "planner", "payment", 1.0))
    res = inv.check(bad)
    assert not res.passed
    assert not res.hard  # topology alone is soft
    assert res.severity > 0


# ---- temporal -------------------------------------------------------------
def test_temporal_learns_orderings(graphs):
    inv = TemporalInvariant()
    inv.learn(graphs)
    assert ("finance", "payment") in inv.orderings
    assert ("payment", "finance") not in inv.orderings


def test_temporal_flags_reorder(graphs):
    inv = TemporalInvariant()
    inv.learn(graphs)
    bad = InteractionGraph("b").extend(
        [
            ev("b", "payment", "x", 1.0),
            ev("b", "finance", "y", 2.0),
        ]
    )
    res = inv.check(bad)
    assert not res.passed
    assert res.hard


# ---- authority ------------------------------------------------------------
def test_authority_flags_unsanctioned_influence(graphs):
    inv = AuthorityInvariant()
    inv.learn(graphs)
    bad = InteractionGraph("b").add_event(
        InteractionEvent(
            execution_id="b",
            source="m",
            target="payment",
            source_role="marketing",
            target_role="payment",
            timestamp=1.0,
        )
    )
    res = inv.check(bad)
    assert not res.passed
    assert res.hard


# ---- engine / validator ---------------------------------------------------
def test_engine_requires_learn(graphs):
    eng = InvariantEngine([TopologyInvariant()])
    with pytest.raises(RuntimeError):
        eng.evaluate(graphs[0])


def test_validator_allows_good(corpus):
    v = RuntimeValidator.from_corpus(corpus)
    assert v.validate_events(good("live")).verdict is Verdict.ALLOW
    assert v.is_allowed(good("live2")) is True


def test_validator_blocks_authority_breach(corpus):
    v = RuntimeValidator.from_corpus(corpus)
    breach = good("live") + [
        InteractionEvent(
            execution_id="live",
            source="m",
            target="payment",
            source_role="marketing",
            target_role="payment",
            timestamp=99.0,
        )
    ]
    assert v.validate_events(breach).verdict is Verdict.BLOCK


def test_validator_blocks_temporal_breach(corpus):
    v = RuntimeValidator.from_corpus(corpus)
    breach = [
        ev("live", "planner", "risk", 1.0),
        ev("live", "risk", "payment", 2.0),
        ev("live", "payment", "finance", 3.0),
        ev("live", "finance", "approval", 4.0),
    ]
    assert v.validate_events(breach).verdict is Verdict.BLOCK


def test_validator_reviews_benign_novelty(corpus):
    v = RuntimeValidator.from_corpus(corpus)
    novel = good("live") + [ev("live", "finance", "audit", 2.5)]
    assert v.validate_events(novel).verdict is Verdict.REVIEW


def test_validate_events_rejects_mixed_executions(corpus):
    v = RuntimeValidator.from_corpus(corpus)
    mixed = good("a") + good("b")
    with pytest.raises(ValueError):
        v.validate_events(mixed)
