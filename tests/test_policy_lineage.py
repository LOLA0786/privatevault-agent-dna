"""Audit set 5 (P1-10): the fired customer-policy rule is named in the
decision record -- policy_id, schema-reserved since drp/0.1, finally
populated."""

import time

from agent_dna.decision import Decision, DecisionEngine
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.policy.checker import PolicyChecker
from agent_dna.policy.schema import parse_policy_dict
from agent_dna.trace import AgentAction
from tests.test_p0_audit import StubScorer

DOC = {
    "policies": [
        {
            "id": "no-bulk-export",
            "capability": "storage.bulk_export",
            "outcome": "block",
            "reason": "bulk export contractually forbidden",
        }
    ]
}


def _act(cap):
    return AgentAction(agent_id="pol-agent", capability=cap, timestamp=time.time())


def _engine():
    return DecisionEngine(
        scorer=StubScorer(),
        policy=PolicyChecker(parse_policy_dict(DOC)),
    )


def test_fired_rule_id_flows_into_result_and_record():
    result = _engine().decide(_act("storage.bulk_export"))
    assert result.decision is Decision.BLOCK
    assert result.triggered_by == "policy"
    assert result.policy_id == "no-bulk-export"

    rec = DecisionRecorder().record(_act("storage.bulk_export"), result)
    assert rec.policy_id == "no-bulk-export"


def test_no_rule_fired_leaves_policy_id_none():
    result = _engine().decide(_act("crm.read_contact"))
    assert result.policy_id is None
    rec = DecisionRecorder().record(_act("crm.read_contact"), result)
    assert rec.policy_id is None
