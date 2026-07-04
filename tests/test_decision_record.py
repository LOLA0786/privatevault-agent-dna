"""DecisionRecord: chaining, sealing, tamper detection, field honesty."""

import time

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import DecisionEngine
from agent_dna.decision_record import (
    GENESIS_HASH,
    build_record,
)
from agent_dna.trace import AgentAction


class StubScorer:
    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.10,
            severity=Severity.INFO,
            reasons=[],
        )


def _decide(cap="crm.read", args=None):
    engine = DecisionEngine(scorer=StubScorer())
    action = AgentAction(
        agent_id="agent-1",
        capability=cap,
        timestamp=time.time(),
        arguments=args or {},
    )
    return action, engine.decide(action)


def test_record_seals_and_verifies():
    action, result = _decide()
    rec = build_record(action, result)
    assert rec.record_hash != ""
    assert rec.verify()


def test_tamper_detected():
    action, result = _decide()
    rec = build_record(action, result)
    rec.reason = "totally legitimate"
    assert not rec.verify()


def test_chain_links():
    a1, r1 = _decide("crm.read")
    rec1 = build_record(a1, r1)
    assert rec1.prev_hash == GENESIS_HASH

    a2, r2 = _decide("email.send")
    rec2 = build_record(
        a2, r2,
        parent_decision=rec1.decision_id,
        prev_hash=rec1.record_hash,
    )
    assert rec2.prev_hash == rec1.record_hash
    assert rec2.parent_decision == rec1.decision_id
    assert rec2.verify()


def test_raw_arguments_never_stored():
    action, result = _decide(args={"account": "ACC-991", "amount": 4_999_000})
    rec = build_record(action, result)
    d = rec.to_dict()
    flat = str(d)
    assert "ACC-991" not in flat
    assert "4999000" not in flat
    assert len(rec.arguments_digest) == 64


def test_unproduced_fields_default_none():
    action, result = _decide()
    rec = build_record(action, result)
    assert rec.goal is None
    assert rec.intent is None
    assert rec.policy_id is None
    assert rec.approval_ref is None
    assert rec.outcome == "pending"
