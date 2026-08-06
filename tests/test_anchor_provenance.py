"""External provenance anchoring: the first record in a chain proves
origin FROM an upstream artifact (anchor_hash), which is a different
property than prev_hash's internal chain-continuity for every record
after it. Motivated by a real review question: don't let the anchor
case collapse into 'just another prev_hash', which would silently
lose the provenance guarantee."""

import time

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import DecisionEngine
from agent_dna.decision_record import GENESIS_HASH, build_record
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.trace import AgentAction


class StubScorer:
    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.0,
            severity=Severity.INFO,
            reasons=[],
        )


def _act(agent="a1"):
    return AgentAction(agent_id=agent, capability="crm.read", timestamp=time.time())


def test_no_anchor_falls_back_to_genesis():
    engine = DecisionEngine(scorer=StubScorer())
    rec = build_record(_act(), engine.decide(_act()))
    assert rec.prev_hash == GENESIS_HASH
    assert rec.verify()


def test_first_record_binds_to_external_anchor():
    engine = DecisionEngine(scorer=StubScorer())
    external_provenance_hash = "e" * 64  # e.g. upstream batch hash
    rec = build_record(
        _act(),
        engine.decide(_act()),
        anchor_hash=external_provenance_hash,
    )
    assert rec.prev_hash == external_provenance_hash
    assert rec.prev_hash != GENESIS_HASH
    assert rec.verify()


def test_anchor_only_applies_to_first_record_not_subsequent():
    """The core property under test: passing anchor_hash on a
    non-first record must be ignored, or the chain-continuity
    property (prev_hash == previous record_hash) would silently
    break."""
    engine = DecisionEngine(scorer=StubScorer())
    rec1 = build_record(_act(), engine.decide(_act()), anchor_hash="e" * 64)
    rec2 = build_record(
        _act(),
        engine.decide(_act()),
        parent_decision=rec1.decision_id,
        prev_hash=rec1.record_hash,
        anchor_hash="f" * 64,  # must be ignored -- there IS a parent
    )
    assert rec2.prev_hash == rec1.record_hash
    assert rec2.prev_hash != "f" * 64
    assert rec2.verify()


def test_recorder_anchors_only_the_agents_first_record():
    engine = DecisionEngine(scorer=StubScorer())
    recorder = DecisionRecorder()
    external_hash = "d" * 64

    rec1 = recorder.record(_act(), engine.decide(_act()), anchor_hash=external_hash)
    assert rec1.prev_hash == external_hash

    # second record for the SAME agent: anchor ignored even if passed
    rec2 = recorder.record(_act(), engine.decide(_act()), anchor_hash="c" * 64)
    assert rec2.prev_hash == rec1.record_hash
    assert rec2.prev_hash != "c" * 64

    assert recorder.graph.verify_chain("a1")


def test_different_agents_can_have_different_anchors():
    """Two agents' chains can independently prove provenance from two
    different upstream batches."""
    engine = DecisionEngine(scorer=StubScorer())
    recorder = DecisionRecorder()

    rec_a = recorder.record(
        _act("agent-a"), engine.decide(_act("agent-a")), anchor_hash="a" * 64
    )
    rec_b = recorder.record(
        _act("agent-b"), engine.decide(_act("agent-b")), anchor_hash="b" * 64
    )

    assert rec_a.prev_hash == "a" * 64
    assert rec_b.prev_hash == "b" * 64
    assert recorder.graph.verify_all() == {"agent-a": True, "agent-b": True}
