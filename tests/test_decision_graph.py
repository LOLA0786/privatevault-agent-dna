"""DecisionGraph + DecisionRecorder: storage, lineage, queries, chain integrity."""

import time

import pytest

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.decision_graph import DecisionGraph
from agent_dna.decision_record import build_record
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.trace import AgentAction


class StubScorer:
    def __init__(self, drift=0.0):
        self.drift = drift

    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=self.drift,
            severity=Severity.INFO,
            reasons=[],
        )


class StubInvariants:
    def __init__(self, forbidden):
        self.forbidden = forbidden

    def validate(self, capability, previous):
        class R:
            pass

        r = R()
        r.violated = capability == self.forbidden
        r.message = "forbidden" if r.violated else ""
        return r


def _engine(drift=0.0, forbidden="wire.drain"):
    return DecisionEngine(
        scorer=StubScorer(drift),
        invariants=StubInvariants(forbidden),
        drift_threshold=0.50,
    )


def _action(cap, agent="agent-1"):
    return AgentAction(
        agent_id=agent,
        capability=cap,
        timestamp=time.time(),
    )


def _recorded_stream(caps, agent="agent-1", drift=0.0):
    engine = _engine(drift=drift)
    recorder = DecisionRecorder()
    prev = None
    for cap in caps:
        a = _action(cap, agent)
        r = engine.decide(a, prev)
        recorder.record(a, r)
        if r.decision == Decision.ALLOW:
            prev = cap
    return recorder


def test_recorder_builds_linked_chain():
    rec = _recorded_stream(["crm.read", "email.send", "crm.read"])
    g = rec.graph
    assert len(g) == 3

    records = list(g)
    assert records[0].parent_decision is None
    assert records[1].parent_decision == records[0].decision_id
    assert records[2].parent_decision == records[1].decision_id
    assert records[1].prev_hash == records[0].record_hash


def test_chain_verification_passes_for_honest_stream():
    rec = _recorded_stream(["crm.read", "email.send"])
    assert rec.graph.verify_chain("agent-1")
    assert rec.graph.verify_all() == {"agent-1": True}


def test_tampered_record_fails_chain_verification():
    rec = _recorded_stream(["crm.read", "email.send"])
    victim = list(rec.graph)[0]
    victim.reason = "rewritten history"
    assert not rec.graph.verify_chain("agent-1")


def test_graph_refuses_unsealed_record():
    engine = _engine()
    a = _action("crm.read")
    r = engine.decide(a)
    record = build_record(a, r)
    record.record_hash = ""  # unseal it
    with pytest.raises(ValueError):
        DecisionGraph().add(record)


def test_graph_refuses_orphan_parent():
    engine = _engine()
    a = _action("crm.read")
    r = engine.decide(a)
    record = build_record(a, r, parent_decision="nonexistent-id")
    with pytest.raises(ValueError):
        DecisionGraph().add(record)


def test_find_blocked_returns_only_blocks():
    rec = _recorded_stream(["crm.read", "wire.drain", "email.send"])
    blocked = rec.graph.find_blocked()
    assert len(blocked) == 1
    assert blocked[0].capability == "wire.drain"
    assert blocked[0].triggered_by == "invariant"


def test_find_by_capability_and_agent():
    rec = _recorded_stream(["crm.read", "crm.read", "email.send"])
    assert len(rec.graph.find_by_capability("crm.read")) == 2
    assert len(rec.graph.find_by_agent("agent-1")) == 3
    assert rec.graph.find_by_agent("nobody") == []


def test_lineage_walks_root_to_node():
    rec = _recorded_stream(["crm.read", "email.send", "storage.export"])
    last = list(rec.graph)[-1]
    path = rec.graph.lineage(last.decision_id)
    assert [p.capability for p in path] == [
        "crm.read",
        "email.send",
        "storage.export",
    ]


def test_descendants_returns_downstream():
    rec = _recorded_stream(["crm.read", "email.send", "storage.export"])
    first = list(rec.graph)[0]
    down = rec.graph.descendants(first.decision_id)
    assert [d.capability for d in down] == ["email.send", "storage.export"]


def test_per_agent_chains_are_independent():
    recorder = DecisionRecorder()
    engine = _engine()
    for agent in ("agent-1", "agent-2"):
        for cap in ("crm.read", "email.send"):
            a = _action(cap, agent)
            recorder.record(a, engine.decide(a))
    assert recorder.graph.verify_all() == {
        "agent-1": True,
        "agent-2": True,
    }
    assert len(recorder.graph.find_by_agent("agent-1")) == 2
