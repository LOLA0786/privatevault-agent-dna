"""Structural invariants on the approval graph.

These hold by definition and need no training corpus -- the only
invariant family here whose correctness does not depend on a learned
baseline. A cycle in `approves` is a contradiction, not an anomaly.
"""

from agent_dna.multi_agent.events import InteractionEvent
from agent_dna.multi_agent.interaction_graph import InteractionGraph
from agent_dna.multi_agent.structure import (
    ApprovalGraph,
    StructuralAuthorityInvariant,
)


def _exec_graph(*events):
    g = InteractionGraph("exec-1")
    for e in events:
        g.add_event(e)
    return g


def _ev(source, target, approval=False, ts=1.0):
    return InteractionEvent(
        execution_id="exec-1", source=source, target=target,
        timestamp=ts, approval=approval,
    )


# ---------------------------------------------------- cycle detection core

def test_acyclic_approval_chain_is_clean():
    g = ApprovalGraph.from_pairs([("ceo", "cfo"), ("cfo", "treasury"),
                                  ("treasury", "payments")])
    assert g.cycles() == []
    assert StructuralAuthorityInvariant.analyse(g) == []


def test_self_approval_detected():
    g = ApprovalGraph.from_pairs([("treasury", "treasury")])
    (v,) = StructuralAuthorityInvariant.analyse(g)
    assert v.kind == "self_approval"
    assert v.agents == ("treasury",)


def test_mutual_approval_detected():
    g = ApprovalGraph.from_pairs([("a", "b"), ("b", "a")])
    (v,) = StructuralAuthorityInvariant.analyse(g)
    assert v.kind == "mutual_approval"
    assert set(v.agents) == {"a", "b"}


def test_three_party_collusion_cycle_detected():
    """The case individual grant checks cannot see: every single grant
    is defensible, the composition is not."""
    g = ApprovalGraph.from_pairs([
        ("treasury", "ops"), ("ops", "audit"), ("audit", "treasury"),
    ])
    (v,) = StructuralAuthorityInvariant.analyse(g)
    assert v.kind == "approval_cycle"
    assert set(v.agents) == {"treasury", "ops", "audit"}
    assert "segregation-of-duties" in v.detail


def test_each_cycle_reported_once_not_per_rotation():
    g = ApprovalGraph.from_pairs([("a", "b"), ("b", "c"), ("c", "a")])
    assert len(g.cycles()) == 1


def test_multiple_independent_cycles_all_reported():
    g = ApprovalGraph.from_pairs([
        ("a", "b"), ("b", "a"),
        ("x", "y"), ("y", "z"), ("z", "x"),
    ])
    kinds = sorted(v.kind for v in StructuralAuthorityInvariant.analyse(g))
    assert kinds == ["approval_cycle", "mutual_approval"]


def test_cycle_output_is_deterministic():
    pairs = [("c", "a"), ("a", "b"), ("b", "c")]
    first = ApprovalGraph.from_pairs(pairs).cycles()
    second = ApprovalGraph.from_pairs(reversed(pairs)).cycles()
    assert first == second


# ------------------------------------------------------------- reachability

def test_reachable_from_is_transitive_closure():
    g = ApprovalGraph.from_pairs([("a", "b"), ("b", "c"), ("c", "d")])
    assert g.reachable_from("a") == {"b", "c", "d"}
    assert g.reachable_from("d") == set()


def test_reachability_terminates_on_a_cycle():
    g = ApprovalGraph.from_pairs([("a", "b"), ("b", "a")])
    assert g.reachable_from("a") == {"a", "b"}


# -------------------------------------- the false-positive guard that matters

def test_ordinary_bidirectional_traffic_is_not_a_violation():
    """A asks B, B answers A. That is normal agent traffic and must NOT
    be read as circular authority. Only approval-carrying edges form the
    antisymmetric relation."""
    graph = _exec_graph(
        _ev("planner", "worker", approval=False),
        _ev("worker", "planner", approval=False),
    )
    result = StructuralAuthorityInvariant().check(graph)
    assert result.passed, result.violations


def test_approval_edges_in_execution_are_checked():
    graph = _exec_graph(
        _ev("agent-a", "agent-b", approval=True),
        _ev("agent-b", "agent-a", approval=True),
    )
    result = StructuralAuthorityInvariant().check(graph)
    assert not result.passed
    assert result.hard
    assert any("mutual_approval" in v for v in result.violations)


# ------------------------------------------------------- Invariant contract

def test_declared_model_is_validated_without_any_execution():
    """Design-time control: the configuration itself is checkable before
    a single agent runs."""
    inv = StructuralAuthorityInvariant(check_execution_graph=False)
    inv.declare(ApprovalGraph.from_pairs([
        ("treasury", "ops"), ("ops", "treasury"),
    ]))
    result = inv.check(_exec_graph())
    assert not result.passed
    assert result.hard


def test_learn_is_a_noop_and_check_still_works():
    """The family needs no corpus. Calling learn with nothing must not
    weaken it."""
    inv = StructuralAuthorityInvariant()
    inv.learn([])
    graph = _exec_graph(_ev("a", "a", approval=True))
    assert not inv.check(graph).passed


def test_clean_execution_passes():
    graph = _exec_graph(
        _ev("supervisor", "worker", approval=True),
        _ev("worker", "tool", approval=False),
    )
    assert StructuralAuthorityInvariant().check(graph).passed


def test_violations_are_hard_not_advisory():
    graph = _exec_graph(_ev("a", "a", approval=True))
    result = StructuralAuthorityInvariant().check(graph)
    assert result.hard is True
    assert result.severity == 1.0


def test_describe_states_no_training_required():
    d = StructuralAuthorityInvariant().describe()
    assert d["requires_training"] is False
