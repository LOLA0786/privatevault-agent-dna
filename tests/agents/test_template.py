"""Agent template (agents/core): every consequential action goes through
PrivateVault, and the pieces are config-driven.

Claims -> tests:
  - A money or external tool cannot be executed without a clearance from the
    gate; a clearance for another tool or another call does not transfer
    -> test_registry_refuses_ungated_execution
  - A persona YAML compiles to rules the real PolicyChecker fires exactly as
    declared, and to a grants file the runtime can load
    -> test_persona_compiles_to_policy_and_grants
  - The scripted model is deterministic and never calls the network
    -> test_scripted_model_is_deterministic
  - The approver kit produces approvals the bridge verifies, and refuses to
    approve for an action digest it was not shown
    -> test_approver_kit_signs_exact_action
  - The receipt log is append-only JSONL with a hash chain
    -> test_receipt_log_chains_entries
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agents.core.approval import ApproverKit, ScriptedApprover
from agents.core.model import Final, ScriptedModel, ToolCall
from agents.core.persona import load_persona
from agents.core.receipts import ReceiptLog
from agents.core.tools import (
    ClearanceRequiredError,
    RiskClass,
    Tool,
    ToolRegistry,
)

PERSONA = Path(__file__).resolve().parents[2] / "agents" / "personas" / "finance_ops"


def _tools() -> ToolRegistry:
    calls: list[tuple[str, dict]] = []
    return ToolRegistry(
        [
            Tool(
                name="lookup",
                description="read something",
                capability="demo.lookup",
                risk=RiskClass.READ,
                execute=lambda args: calls.append(("lookup", args)) or {"ok": True},
            ),
            Tool(
                name="notify",
                description="send a message",
                capability="demo.notify",
                risk=RiskClass.EXTERNAL,
                execute=lambda args: calls.append(("notify", args)) or {"sent": True},
            ),
            Tool(
                name="email",
                description="send an email",
                capability="demo.email",
                risk=RiskClass.EXTERNAL,
                execute=lambda args: calls.append(("email", args)) or {"sent": True},
            ),
        ]
    )


def test_registry_refuses_ungated_execution():
    registry = _tools()
    assert registry.execute("lookup", {"q": 1}) == {"ok": True}
    with pytest.raises(ClearanceRequiredError):
        registry.execute("notify", {"to": "ap"})
    clearance = registry.clearance_for("notify", {"to": "ap"}, decision_id="d-1")
    assert registry.execute("notify", {"to": "ap"}, clearance=clearance) == {
        "sent": True
    }
    # Different arguments: the clearance does not transfer.
    with pytest.raises(ClearanceRequiredError):
        registry.execute("notify", {"to": "cfo"}, clearance=clearance)
    # Different tool: refused too.
    with pytest.raises(ClearanceRequiredError):
        registry.execute("email", {"to": "ap"}, clearance=clearance)
    # A clearance is single-use.
    with pytest.raises(ClearanceRequiredError):
        registry.execute("notify", {"to": "ap"}, clearance=clearance)


def test_persona_compiles_to_policy_and_grants(tmp_path):
    from agent_dna.policy.checker import PolicyChecker
    from agent_dna.policy.loader import load_policy_file

    persona = load_persona(PERSONA / "persona.yaml")
    assert persona.agent_id == "ap-agent-01"
    assert persona.organisation_id == "lender.example"
    compiled = persona.compile(tmp_path)
    checker = PolicyChecker(load_policy_file(compiled.policy_file))
    cap = "payments.pay_invoice"

    def check(args):
        return checker.check(agent_id=persona.agent_id, capability=cap, arguments=args)

    ok = {"amount": 4200, "currency": "INR", "payee_id": "V-100", "po_matched": True}
    assert not check(ok).fired
    big = dict(ok, amount=18000)
    assert check(big).fired and check(big).outcome == "require_approval"
    huge = dict(ok, amount=60000)
    assert check(huge).fired and check(huge).outcome == "block"
    stranger = dict(ok, payee_id="V-999")
    assert check(stranger).fired and check(stranger).outcome == "block"
    no_po = dict(ok, po_matched=False)
    assert check(no_po).fired and check(no_po).outcome == "require_approval"
    # First firing rule wins: an unknown payee above the hard cap is blocked
    # for the payee, which is the more specific reason.
    both = dict(ok, payee_id="V-999", amount=99000)
    assert check(both).matched_rule_id.endswith("unknown-payee")

    grants = json.loads(Path(compiled.grants_file).read_text())
    pay = next(g for g in grants if g["capability"] == cap)
    assert pay["agent_id"] == persona.agent_id and pay["budget"] == 100000
    assert any(g["capability"] == "comms.notify_ap" for g in grants)


def test_scripted_model_is_deterministic():
    script = [ToolCall("lookup", {"q": 1}), Final("done")]
    model = ScriptedModel(script)
    first = model.next_step(history=[], tools=[])
    assert first == ToolCall("lookup", {"q": 1})
    assert model.next_step(history=[{"tool": "lookup"}], tools=[]) == Final("done")
    with pytest.raises(RuntimeError, match="script exhausted"):
        model.next_step(history=[], tools=[])


def test_approver_kit_signs_exact_action(tmp_path):
    from agent_dna.action_v01 import execution_action_digest
    from agent_dna.approval_bridge import ApprovalBridge, ApprovalContext
    from agent_dna.approval_v01 import approval_artifact_digest
    from agent_dna.sqlite_store import SQLiteDecisionStore

    kit = ApproverKit("lender.example", principal="cfo@lender.example", key_id="cfo")
    action = {
        "subject_principal": "ap-agent-01@lender.example",
        "subject_key_id": "ap-agent-01",
        "action": "payments.pay_invoice",
        "resource": "vendor:V-100",
        "parameters": {"amount": 18000, "currency": "INR", "payee_id": "V-100"},
    }
    approver = ScriptedApprover(
        kit, decide=lambda a, reason: a["parameters"]["amount"] < 20000
    )
    approval = approver.review(action, request_id="req-1", reason="above threshold")
    assert approval is not None
    assert approval["artifact"]["action_digest"] == execution_action_digest(action)
    bridge = ApprovalBridge(
        trust_bundle=kit.bundle, ledger=SQLiteDecisionStore(str(tmp_path / "a.db"))
    )
    verdict = bridge.consider(
        approval,
        context=ApprovalContext(
            expected_action_digest=execution_action_digest(action),
            requester_identities=frozenset({"ap-agent-01"}),
        ),
        agent_id="ap-agent-01",
    )
    assert verdict.ok, verdict.detail
    assert verdict.artifact_digest == approval_artifact_digest(approval["artifact"])
    # The scripted reviewer declines a larger action: no artifact at all.
    big = dict(action, parameters={**action["parameters"], "amount": 25000})
    assert approver.review(big, request_id="req-2", reason="above threshold") is None


def test_receipt_log_chains_entries(tmp_path):
    log = ReceiptLog(tmp_path / "receipts.jsonl")
    log.record({"step": 1, "decision": "allow"})
    log.record({"step": 2, "decision": "block"})
    entries = log.entries()
    assert [e["step"] for e in entries] == [1, 2]
    assert entries[0]["prev_hash"] == "0" * 64
    assert entries[1]["prev_hash"] == entries[0]["entry_hash"]
    assert log.verify() is True
    lines = (tmp_path / "receipts.jsonl").read_text().splitlines()
    tampered = json.loads(lines[0])
    tampered["decision"] = "allow!"
    (tmp_path / "receipts.jsonl").write_text(
        json.dumps(tampered) + "\n" + lines[1] + "\n"
    )
    assert ReceiptLog(tmp_path / "receipts.jsonl").verify() is False
