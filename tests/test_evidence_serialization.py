"""DecisionResult.to_dict must not drop the evidence layer."""

import time

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import DecisionEngine, Decision
from agent_dna.trace import AgentAction


class StubScorer:
    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.65,
            severity=Severity.INFO,
            reasons=["stub drift"],
        )


def test_to_dict_carries_evidence():
    engine = DecisionEngine(scorer=StubScorer(), drift_threshold=0.50)
    result = engine.decide(
        AgentAction(
            agent_id="agent-1",
            capability="crm.read",
            timestamp=time.time(),
        )
    )
    d = result.to_dict()

    assert "evidence" in d
    assert "evidence_strength" in d
    assert len(d["evidence"]) >= 1
    assert d["evidence"][0]["name"] == "Behavioral Drift"
    assert d["evidence_strength"] > 0.0

    import json
    json.dumps(d)
