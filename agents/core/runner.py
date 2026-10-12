"""The agent loop. The model proposes; PrivateVault decides; the runner obeys.

For each proposed tool call:
- READ tools run locally, no decision.
- Everything else is decided. REQUIRE_APPROVAL goes to the approver, who may
  sign for exactly this action; the decision is then re-asked with the
  approval. BLOCK ends the step. A refused approval never changes a verdict.
- An allowed MONEY tool is minted into a permit and dispatched through the
  sidecar; the receiver's receipt digest comes back with the response.
- An allowed EXTERNAL tool runs locally under a single-use clearance.

Every gated step is written to the receipt log. Nothing is retried.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agents.core.approval import Approver
from agents.core.gate import DecisionOutcome, PermitBundle, PrivateVaultGate, wire_for
from agents.core.model import Final, Model, ToolCall
from agents.core.receipts import ReceiptLog
from agents.core.tools import ClearanceRequiredError, RiskClass, ToolRegistry


@dataclass
class StepResult:
    tool: str
    arguments: dict[str, Any]
    decision: str | None = None
    first_decision: str | None = None
    triggered_by: str | None = None
    reason: str | None = None
    policy_id: str | None = None
    decision_id: str | None = None
    approval: dict[str, Any] | None = None
    approval_digest: str | None = None
    permit_bundle: PermitBundle | None = None
    dispatch_outcome: str | None = None
    dispatch_reason: str | None = None
    receiver_receipt_digest: str | None = None
    receiver_sequence: int | None = None
    result: Any = None
    error: str | None = None

    @property
    def permit(self) -> dict[str, Any] | None:
        return None if self.permit_bundle is None else self.permit_bundle.authorization

    @property
    def wire(self) -> bytes:
        return wire_for(self.arguments)

    def summary(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "decision": self.decision,
            "triggered_by": self.triggered_by,
            "reason": self.reason,
            "dispatch_outcome": self.dispatch_outcome,
            "receiver_sequence": self.receiver_sequence,
            "result": self.result,
            "error": self.error,
        }


@dataclass
class RunReport:
    steps: list[StepResult] = field(default_factory=list)
    final: str | None = None

    def step(self, tool: str) -> StepResult:
        for step in self.steps:
            if step.tool == tool:
                return step
        raise KeyError(f"no step used tool {tool!r}")


class AgentRunner:
    def __init__(
        self,
        *,
        model: Model,
        registry: ToolRegistry,
        gate: PrivateVaultGate,
        approver: Approver | None,
        receipts: ReceiptLog,
        max_steps: int = 25,
    ) -> None:
        self.model = model
        self.registry = registry
        self.gate = gate
        self.approver = approver
        self.receipts = receipts
        self.max_steps = max_steps

    def run(self, goal: str) -> RunReport:
        report = RunReport()
        history: list[dict[str, Any]] = [{"goal": goal}]
        for _ in range(self.max_steps):
            step = self.model.next_step(history, self.registry.tools)
            if isinstance(step, Final):
                report.final = step.text
                break
            assert isinstance(step, ToolCall)
            result = self._perform(step)
            report.steps.append(result)
            history.append(result.summary())
        return report

    def _perform(self, call: ToolCall) -> StepResult:
        tool = self.registry.get(call.name)
        arguments = tool.arguments_for(call.arguments)
        result = StepResult(tool=tool.name, arguments=arguments)
        if tool.risk is RiskClass.READ:
            result.decision = "local"
            result.result = self.registry.execute(tool.name, arguments)
            return result

        request_id = self.gate.new_request_id()
        outcome = self.gate.decide(tool, arguments, request_id=request_id)
        result.first_decision = outcome.decision
        if outcome.decision == "require_approval" and self.approver is not None:
            action = tool.execution_action(
                self.gate.agent_id, self.gate.organisation_id, arguments
            )
            approval = self.approver.review(
                action, request_id=request_id, reason=outcome.reason
            )
            if approval is not None and tool.risk is RiskClass.MONEY:
                result.approval = approval
                outcome = self.gate.decide(
                    tool, arguments, approval=approval, request_id=request_id
                )
        self._apply(outcome, result)
        if outcome.allowed:
            self._execute(tool, arguments, outcome, result)
        self._log(result)
        return result

    @staticmethod
    def _apply(outcome: DecisionOutcome, result: StepResult) -> None:
        result.decision = outcome.decision
        result.triggered_by = outcome.triggered_by
        result.reason = outcome.reason
        result.policy_id = outcome.policy_id
        result.decision_id = (
            None if outcome.record is None else outcome.record["decision_id"]
        )
        if outcome.triggered_by == "approval":
            result.approval_digest = outcome.approval_ref

    def _execute(
        self,
        tool,
        arguments: dict[str, Any],
        outcome: DecisionOutcome,
        result: StepResult,
    ) -> None:
        if tool.risk is RiskClass.MONEY:
            permit = self.gate.mint(outcome, tool, arguments)
            result.permit_bundle = permit
            dispatched = self.gate.dispatch(permit, tool, arguments)
            result.dispatch_outcome = dispatched.outcome
            result.dispatch_reason = dispatched.reason_code
            transport = getattr(self.gate.dispatcher, "transport", None)
            headers = getattr(transport, "last_response_headers", {}) or {}
            if dispatched.outcome == "EXECUTED":
                result.receiver_receipt_digest = headers.get("x-pv-receiver-receipt")
                seq = headers.get("x-pv-receiver-sequence")
                result.receiver_sequence = int(seq) if seq else None
                result.result = dispatched.transport_response
            return
        assert outcome.record is not None
        clearance = self.registry.clearance_for(
            tool.name, arguments, decision_id=outcome.record["decision_id"]
        )
        try:
            result.result = self.registry.execute(
                tool.name, arguments, clearance=clearance
            )
        except ClearanceRequiredError as exc:
            result.error = str(exc)

    def _log(self, result: StepResult) -> None:
        self.receipts.record(
            {
                "tool": result.tool,
                "decision_id": result.decision_id,
                "decision": result.decision,
                "first_decision": result.first_decision,
                "triggered_by": result.triggered_by,
                "policy_id": result.policy_id,
                "approval_digest": result.approval_digest,
                "permit_id": None
                if result.permit_bundle is None
                else result.permit_bundle.permit_id,
                "dispatch_outcome": result.dispatch_outcome,
                "dispatch_reason": result.dispatch_reason,
                "receiver_receipt_digest": result.receiver_receipt_digest,
                "receiver_sequence": result.receiver_sequence,
            }
        )
