"""drp/0.1 conformance: version pinned, request_id flows, hash-covered."""

import time

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import DecisionEngine
from agent_dna.decision_record import build_record
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


def _pair(request_id=None):
    engine = DecisionEngine(scorer=StubScorer())
    a = AgentAction(agent_id="a1", capability="crm.read", timestamp=time.time())
    return build_record(a, engine.decide(a), request_id=request_id)


def test_protocol_version_present_and_hashed():
    rec = _pair()
    d = rec.to_dict()
    assert d["protocol_version"] == "drp/0.1"
    assert rec.verify()
    rec.protocol_version = "drp/9.9"
    assert not rec.verify()          # version is inside the digest


def test_request_id_flows_and_is_hashed():
    rec = _pair(request_id="req-8842")
    assert rec.to_dict()["request_id"] == "req-8842"
    assert rec.verify()
    rec.request_id = "req-FORGED"
    assert not rec.verify()


def test_request_id_defaults_null():
    assert _pair().to_dict()["request_id"] is None
