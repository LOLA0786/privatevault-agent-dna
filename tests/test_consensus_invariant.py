"""Tests for the consensus invariant (Phase 2)."""
from __future__ import annotations

import pytest

from agent_dna.multi_agent import (
    ConsensusInvariant,
    GraphBuilder,
    InteractionEvent,
    RuntimeValidator,
    Verdict,
)


def step(exec_id, src, dst, sr, dr, t, **kw):
    return InteractionEvent(execution_id=exec_id, source=src, target=dst,
                            source_role=sr, target_role=dr, timestamp=t, **kw)


def signoff(exec_id, role, t, approve=True, confidence=0.95):
    return InteractionEvent(
        execution_id=exec_id, source=f"{role}_agent", target="ledger",
        source_role=role, target_role="ledger", timestamp=t,
        approval=approve, confidence=confidence,
        metadata={"is_signoff": True})


def good(exec_id, *, skip=None, dissent=None, early_payment=False, conf=0.95):
    ev = [
        step(exec_id, "planner", "risk", "planning", "risk", 1.0),
        step(exec_id, "risk", "finance", "risk", "finance", 2.0),
        step(exec_id, "finance", "approval", "finance", "approval", 3.0),
    ]
    if early_payment:
        ev.append(step(exec_id, "approval", "payment", "approval", "payment", 2.5))
    t = 3.2
    for role in ("risk", "finance", "approval"):
        if skip == role:
            t += 0.2
            continue
        ev.append(signoff(exec_id, role, t,
                        approve=(dissent != role), confidence=conf))
        t += 0.2
    if not early_payment:
        ev.append(step(exec_id, "approval", "payment", "approval", "payment", 4.0))
    return ev


@pytest.fixture
def corpus():
    out = []
    for i in range(60):
        out.extend(good(f"t-{i}"))
    return out


@pytest.fixture
def graphs(corpus):
    return GraphBuilder().ingest_many(corpus).build_all()


def test_learns_payment_requires_three_approvers(graphs):
    inv = ConsensusInvariant()
    inv.learn(graphs)
    assert inv.required_approvers.get("payment") == {"risk", "finance", "approval"}


def test_only_payment_is_constrained(graphs):
    inv = ConsensusInvariant()
    inv.learn(graphs)
    # sign-offs cluster just before payment, so no other gate acquires a rule
    assert set(inv.required_approvers) == {"payment"}


def test_silent_approver_blocks(graphs):
    inv = ConsensusInvariant()
    inv.learn(graphs)
    g = GraphBuilder().ingest_many(good("x", skip="finance")).get("x")
    res = inv.check(g)
    assert not res.passed and res.hard
    assert any("finance" in v and "silent" in v for v in res.violations)


def test_dissent_blocks_and_is_labeled(graphs):
    inv = ConsensusInvariant()
    inv.learn(graphs)
    g = GraphBuilder().ingest_many(good("x", dissent="risk")).get("x")
    res = inv.check(g)
    assert not res.passed and res.hard
    assert any("risk dissented" in v for v in res.violations)


def test_early_action_blocks(graphs):
    inv = ConsensusInvariant()
    inv.learn(graphs)
    g = GraphBuilder().ingest_many(good("x", early_payment=True)).get("x")
    res = inv.check(g)
    assert not res.passed and res.hard


def test_clean_execution_passes(graphs):
    inv = ConsensusInvariant()
    inv.learn(graphs)
    g = GraphBuilder().ingest_many(good("x")).get("x")
    assert inv.check(g).passed


def test_silent_when_no_signoff_structure():
    # corpus with no approvals at all -> consensus must learn nothing
    plain = []
    for i in range(20):
        plain.append(step(f"p{i}", "a", "b", "ra", "rb", 1.0))
        plain.append(step(f"p{i}", "b", "c", "rb", "rc", 2.0))
    graphs = GraphBuilder().ingest_many(plain).build_all()
    inv = ConsensusInvariant()
    inv.learn(graphs)
    assert inv.required_approvers == {}


def test_min_confidence_rejects_weak_signoff(graphs):
    # an approver that signs off below the confidence floor is not counted
    inv = ConsensusInvariant(min_confidence=0.8)
    inv.learn(graphs)
    assert inv.required_approvers.get("payment") == {"risk", "finance", "approval"}
    weak = good("x")
    # rebuild with finance signing off at low confidence
    weak = good("x", conf=0.5)
    g = GraphBuilder().ingest_many(weak).get("x")
    res = inv.check(g)
    # every approver now below floor -> all silent -> breach
    assert not res.passed and res.hard


def test_validator_blocks_consensus_breach(corpus):
    v = RuntimeValidator.from_corpus(corpus)
    assert v.validate_events(good("live")).verdict is Verdict.ALLOW
    assert v.validate_events(good("live", skip="finance")).verdict is Verdict.BLOCK
    assert v.validate_events(good("live", dissent="risk")).verdict is Verdict.BLOCK
