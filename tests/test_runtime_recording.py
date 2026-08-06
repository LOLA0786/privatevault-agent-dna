"""RuntimeMonitor + DecisionRecorder integration: the full pipeline."""

import time

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.runtime import RuntimeMonitor
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


class StubInvariants:
    def validate(self, capability, previous):
        class R:
            pass

        r = R()
        r.violated = capability == "wire.drain"
        r.message = "forbidden" if r.violated else ""
        return r


def _action(cap):
    return AgentAction(
        agent_id="agent-1",
        capability=cap,
        timestamp=time.time(),
    )


def test_monitor_records_every_decision():
    recorder = DecisionRecorder()
    engine = DecisionEngine(
        scorer=StubScorer(),
        invariants=StubInvariants(),
    )
    m = RuntimeMonitor(engine, recorder=recorder)

    m.process(_action("crm.read"))  # ALLOW
    m.process(_action("wire.drain"))  # BLOCK
    m.process(_action("email.send"))  # ALLOW

    g = recorder.graph
    assert len(g) == 3  # blocks recorded too
    assert len(g.find_blocked()) == 1
    assert g.find_blocked()[0].capability == "wire.drain"
    assert g.verify_chain("agent-1")


def test_monitor_without_recorder_unchanged():
    engine = DecisionEngine(
        scorer=StubScorer(),
        invariants=StubInvariants(),
    )
    m = RuntimeMonitor(engine)
    result = m.process(_action("wire.drain"))
    assert result.decision == Decision.BLOCK
    assert m.event_count == 1
