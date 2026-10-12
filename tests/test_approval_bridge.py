"""Approval bridge (ADR 0020): a verified, single-use approval turns a
REQUIRE_APPROVAL verdict into an ALLOW bound to the same action.

Claims -> tests:
  - A valid approval from a pinned approver turns policy/authorization
    REQUIRE_APPROVAL into ALLOW, triggered_by "approval", and the sealed
    record carries the artifact digest in approval_ref
    -> test_valid_approval_allows_and_is_sealed_into_the_record
  - Single use: the same artifact cannot produce a second ALLOW, even
    through a fresh store instance on the same file
    -> test_approval_is_consumed_atomically_and_durably
  - Separation of duties: approver identity equal to the requesting agent
    or caller is refused
    -> test_approver_must_differ_from_requester
  - Approval for action X does not unlock action Y
    -> test_approval_for_other_action_is_refused
  - Expired artifact refused; approver key not in the pinned bundle refused
    -> test_expired_approval_is_refused
    -> test_unpinned_approver_is_refused
  - No approver bundle pinned: an approval never changes the verdict
    -> test_without_bridge_an_approval_changes_nothing
  - An approval never overrides BLOCK and is not consumed on a plain ALLOW
    -> test_approval_cannot_override_block_and_is_not_burned_on_allow
  - An audit-only decide (no execution action) cannot use an approval
    -> test_approval_requires_a_bound_decision
  - A ledger fault refuses rather than allowing
    -> test_ledger_fault_refuses
  - A DENY artifact is not an approval
    -> test_deny_artifact_is_refused
"""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from agent_dna.action_v01 import execution_action_digest
from agent_dna.approval_bridge import (
    APPROVAL_ACTION_MISMATCH,
    APPROVAL_ALREADY_USED,
    APPROVAL_INVALID,
    APPROVAL_LEDGER_UNAVAILABLE,
    APPROVAL_NOT_CONFIGURED,
    APPROVAL_REQUIRES_BOUND_DECISION,
    APPROVAL_SEPARATION_OF_DUTIES,
    ApprovalBridge,
    ApprovalContext,
)
from agent_dna.approval_v01 import approval_artifact_digest
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.decision_record import build_record_v02
from agent_dna.grants import GrantRegistry
from agent_dna.sqlite_store import SQLiteDecisionStore
from agent_dna.trace import AgentAction
from tests.approval_world import ApproverWorld

ORG = "lender.example"
AGENT = "ap-agent-01"
CAP = "payments.pay_invoice"


def _execution_action(amount: int = 18000, payee: str = "V-100") -> dict:
    return {
        "subject_principal": f"{AGENT}@{ORG}",
        "subject_key_id": AGENT,
        "action": CAP,
        "resource": f"vendor:{payee}",
        "parameters": {"amount": amount, "currency": "INR", "payee_id": payee},
    }


def _dispatch_context() -> dict:
    return {
        "adapter": "https",
        "transport": "https",
        "operation": "POST /api/v1/transfers",
        "destination": "https://payments.partner.example",
        "serialization": "pv-json-parameters/0.1",
        "wire_content_type": "application/json",
    }


class _Scorer:
    def score(self, action, prev=None):
        from agent_dna.advisory import AdvisorySignal, Posture, Severity

        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.0,
            severity=Severity.INFO,
            components={},
            reasons=[],
            recommended_posture=Posture.LOG,
        )


class World:
    def __init__(self, tmp_path, *, bridge: bool = True):
        self.approver = ApproverWorld(ORG)
        self.store = SQLiteDecisionStore(str(tmp_path / "pv.db"))
        self.path = tmp_path / "pv.db"
        # No grant for CAP: the authorization level says REQUIRE_APPROVAL.
        self.engine = DecisionEngine(
            scorer=_Scorer(),
            authorizer=GrantRegistry(),
            approvals=ApprovalBridge(
                trust_bundle=self.approver.bundle, ledger=self.store
            )
            if bridge
            else None,
        )

    def action(self, amount: int = 18000, payee: str = "V-100") -> AgentAction:
        return AgentAction(
            agent_id=AGENT,
            capability=CAP,
            timestamp=1_760_000_000.0,
            arguments={"amount": amount, "currency": "INR", "payee_id": payee},
            request_id="req-inv-1",
        )

    def context(self, execution_action: dict | None, *, callers=()) -> ApprovalContext:
        return ApprovalContext(
            expected_action_digest=(
                None
                if execution_action is None
                else execution_action_digest(execution_action)
            ),
            requester_identities=frozenset({AGENT, f"{AGENT}@{ORG}", *callers}),
        )

    def decide(self, approval, execution_action=None, *, amount=18000, callers=()):
        execution_action = (
            _execution_action(amount) if execution_action is None else execution_action
        )
        return self.engine.decide(
            self.action(amount),
            approval=approval,
            approval_context=self.context(execution_action, callers=callers),
        )


def test_valid_approval_allows_and_is_sealed_into_the_record(tmp_path):
    w = World(tmp_path)
    ea = _execution_action()
    approval = w.approver.approve(ea, request_id="req-inv-1")

    without = w.engine.decide(w.action())
    assert without.decision is Decision.REQUIRE_APPROVAL

    result = w.decide(approval, ea)
    assert result.decision is Decision.ALLOW, result.reason
    assert result.triggered_by == "approval"
    digest = approval_artifact_digest(approval["artifact"])
    assert result.approval_artifact_digest == digest
    assert w.approver.approver_principal in result.reason

    record = build_record_v02(
        w.action(), result, execution_action=ea, dispatch_context=_dispatch_context()
    )
    assert record.approval_ref == digest
    assert record.triggered_by == "approval"
    assert record.verify()


def test_approval_is_consumed_atomically_and_durably(tmp_path):
    w = World(tmp_path)
    ea = _execution_action()
    approval = w.approver.approve(ea, request_id="req-inv-1")
    assert w.decide(approval, ea).decision is Decision.ALLOW

    again = w.decide(approval, ea)
    assert again.decision is Decision.REQUIRE_APPROVAL
    assert APPROVAL_ALREADY_USED in again.reason
    assert again.approval_artifact_digest is None

    # Restart: a fresh store on the same file still remembers the claim.
    reopened = SQLiteDecisionStore(str(w.path))
    engine = DecisionEngine(
        scorer=_Scorer(),
        authorizer=GrantRegistry(),
        approvals=ApprovalBridge(trust_bundle=w.approver.bundle, ledger=reopened),
    )
    after_restart = engine.decide(
        w.action(), approval=approval, approval_context=w.context(ea)
    )
    assert after_restart.decision is Decision.REQUIRE_APPROVAL
    assert APPROVAL_ALREADY_USED in after_restart.reason


def test_approver_must_differ_from_requester(tmp_path):
    w = World(tmp_path)
    ea = _execution_action()
    # The agent approves its own action: same principal as the subject.
    self_approver = ApproverWorld(
        ORG, approver_principal=f"{AGENT}@{ORG}", approver_key_id="self"
    )
    engine = DecisionEngine(
        scorer=_Scorer(),
        authorizer=GrantRegistry(),
        approvals=ApprovalBridge(trust_bundle=self_approver.bundle, ledger=w.store),
    )
    approval = self_approver.approve(ea, request_id="req-inv-1")
    result = engine.decide(
        w.action(), approval=approval, approval_context=w.context(ea)
    )
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert APPROVAL_SEPARATION_OF_DUTIES in result.reason

    # The approver is a different key but the same identity as the API caller.
    approval = w.approver.approve(ea, request_id="req-inv-1")
    result = w.decide(approval, ea, callers=(w.approver.approver_principal,))
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert APPROVAL_SEPARATION_OF_DUTIES in result.reason
    # A refused approval is not consumed: the same artifact works for a
    # request from someone else.
    assert w.decide(approval, ea).decision is Decision.ALLOW


def test_approval_for_other_action_is_refused(tmp_path):
    w = World(tmp_path)
    approved = _execution_action(amount=18000)
    presented = _execution_action(amount=48000)
    approval = w.approver.approve(approved, request_id="req-inv-1")
    result = w.decide(approval, presented, amount=48000)
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert APPROVAL_ACTION_MISMATCH in result.reason
    # Payee swap with the same amount is a different action too.
    swapped = _execution_action(amount=18000, payee="V-999")
    result = w.decide(approval, swapped)
    assert APPROVAL_ACTION_MISMATCH in result.reason
    # And the original still works: nothing was burned by the mismatches.
    assert w.decide(approval, approved).decision is Decision.ALLOW


def test_expired_approval_is_refused(tmp_path):
    w = World(tmp_path)
    ea = _execution_action()
    old = datetime.now(UTC) - timedelta(minutes=30)
    approval = w.approver.approve(
        ea, request_id="req-inv-1", now=old, artifact_ttl_s=60
    )
    result = w.decide(approval, ea)
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert APPROVAL_INVALID in result.reason
    assert "not valid at execution time" in result.reason


def test_unpinned_approver_is_refused(tmp_path):
    w = World(tmp_path)
    ea = _execution_action()
    rogue = ApproverWorld(
        ORG, approver_principal="rogue@lender.example", approver_key_id="rogue"
    )
    # Signed by a key the pinned bundle does not carry.
    approval = rogue.approve(ea, request_id="req-inv-1")
    result = w.decide(approval, ea)
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert APPROVAL_INVALID in result.reason and "TRUST_ROOT_UNKNOWN" in result.reason
    # Same key id as the real approver, different private key: signature fails.
    forged = rogue.approve(
        ea,
        request_id="req-inv-1",
        approver_principal=w.approver.approver_principal,
        approver_key_id=w.approver.approver_key_id,
    )
    result = w.decide(forged, ea)
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert "SIGNATURE_INVALID" in result.reason or "AUTHORITY" in result.reason


def test_without_bridge_an_approval_changes_nothing(tmp_path):
    w = World(tmp_path, bridge=False)
    ea = _execution_action()
    approval = w.approver.approve(ea, request_id="req-inv-1")
    result = w.decide(approval, ea)
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert APPROVAL_NOT_CONFIGURED in result.reason


def test_approval_cannot_override_block_and_is_not_burned_on_allow(tmp_path):
    import json

    from agent_dna.policy.checker import PolicyChecker
    from agent_dna.policy.loader import load_policy_file

    w = World(tmp_path)
    ea = _execution_action(amount=60000)
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "version": "1.0",
                "policies": [
                    {
                        "id": "hard-cap",
                        "capability": CAP,
                        "outcome": "block",
                        "reason": "above hard cap",
                        "condition": {
                            "field": "arguments.amount",
                            "operator": ">",
                            "value": 50000,
                        },
                    }
                ],
            }
        )
    )
    w.engine.policy = PolicyChecker(load_policy_file(policy_path))
    approval = w.approver.approve(ea, request_id="req-inv-1")
    result = w.decide(approval, ea, amount=60000)
    assert result.decision is Decision.BLOCK
    assert result.approval_artifact_digest is None

    # Plain ALLOW (grant present): the approval is irrelevant and not consumed.
    w.engine.policy = None
    registry = GrantRegistry()
    registry.grant(agent_id=AGENT, capability=CAP, granted_by="ops")
    w.engine.authorizer = registry
    small = _execution_action(amount=1000)
    approval = w.approver.approve(small, request_id="req-inv-1")
    result = w.decide(approval, small, amount=1000)
    assert result.decision is Decision.ALLOW
    assert result.triggered_by != "approval"
    assert result.approval_artifact_digest is None
    assert not w.store.is_approval_consumed(
        approval_artifact_digest(approval["artifact"])
    )


def test_approval_requires_a_bound_decision(tmp_path):
    w = World(tmp_path)
    ea = _execution_action()
    approval = w.approver.approve(ea, request_id="req-inv-1")
    result = w.engine.decide(
        w.action(), approval=approval, approval_context=w.context(None)
    )
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert APPROVAL_REQUIRES_BOUND_DECISION in result.reason


def test_ledger_fault_refuses(tmp_path):
    w = World(tmp_path)
    ea = _execution_action()
    approval = w.approver.approve(ea, request_id="req-inv-1")

    class Broken:
        def try_consume_approval(self, *a, **k):
            raise sqlite3.OperationalError("disk I/O error")

    w.engine.approvals = ApprovalBridge(trust_bundle=w.approver.bundle, ledger=Broken())
    result = w.decide(approval, ea)
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert APPROVAL_LEDGER_UNAVAILABLE in result.reason


def test_deny_artifact_is_refused(tmp_path):
    w = World(tmp_path)
    ea = _execution_action()
    approval = w.approver.approve(ea, request_id="req-inv-1", decision="DENY")
    result = w.decide(approval, ea)
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert APPROVAL_INVALID in result.reason


def test_bridge_refuses_a_bundle_without_an_approval_signer(tmp_path):
    w = World(tmp_path)
    bundle = dict(w.approver.bundle)
    bundle["keys"] = [k for k in bundle["keys"] if "approval_signer" not in k["usages"]]
    with pytest.raises(ValueError, match="approval_signer"):
        ApprovalBridge(trust_bundle=bundle, ledger=w.store)
