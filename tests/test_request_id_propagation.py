"""request_id must survive from the API request into the sealed
decision record.

Reproduce (confirmed 2026-07-22): the API model accepted request_id
and the DecisionRecord schema had a slot for it, but the pipe between
them was never connected -- AgentAction had no field, the API never
copied req.request_id into the action, and the recorder never threaded
it into the record. A correlation id supplied by the caller silently
became null before sealing. This test pins the end-to-end contract.
"""

import tempfile
from pathlib import Path

from agent_dna.decision import DecisionEngine
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.decision_store import DecisionStore
from agent_dna.trace import AgentAction


def _recorder():
    path = Path(tempfile.mkdtemp()) / "decisions.jsonl"
    return DecisionRecorder(store=DecisionStore(str(path)))


def test_agent_action_carries_request_id():
    a = AgentAction(
        agent_id="a1",
        capability="crm.read_contact",
        timestamp=1.0,
        request_id="req-abc-123",
    )
    assert a.request_id == "req-abc-123"


def test_request_id_reaches_the_sealed_record():
    engine = DecisionEngine()
    recorder = _recorder()
    action = AgentAction(
        agent_id="a1",
        capability="crm.read_contact",
        timestamp=1.0,
        request_id="req-abc-123",
    )
    result = engine.decide(action)
    record = recorder.record(action, result)
    assert record.request_id == "req-abc-123", (
        "request_id was dropped between the action and the sealed record"
    )


def test_absent_request_id_is_null_not_an_error():
    engine = DecisionEngine()
    recorder = _recorder()
    action = AgentAction(agent_id="a1", capability="crm.read_contact", timestamp=1.0)
    record = recorder.record(action, engine.decide(action))
    assert record.request_id is None
