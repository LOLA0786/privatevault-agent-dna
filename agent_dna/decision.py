"""
Unified Runtime Decision Engine.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable

from .advisory import AdvisorySignal, Severity
from .amount import (
    INVALID_AMOUNT,
    INVALID_AMOUNT_REASON,
    InvalidAmountError,
    coerce_amount,
)
from .evidence import EvidenceEngine, EvidenceReport
from .trace import AgentAction

_fault_log = logging.getLogger("pv.engine")


def fault_reason(exc: BaseException, label: str = "engine_fault") -> str:
    """Auditable reason for a fail-closed fault, without the exception text.

    The reason is sealed into the decision record, returned to the caller
    and exported to auditors. Exception messages can carry file paths,
    connection strings or evidence values, so only the exception type, an
    optional class-level ``public_reason`` constant and a fault id go there;
    the full exception is logged under the same id.
    """
    fault_id = uuid.uuid4().hex[:16]
    _fault_log.error(
        "%s fault_id=%s %s: %s",
        label,
        fault_id,
        type(exc).__name__,
        exc,
        exc_info=(type(exc), exc, exc.__traceback__),
    )
    public = getattr(type(exc), "public_reason", None)
    detail = f": {public}" if isinstance(public, str) and public else ""
    return f"{label}: {type(exc).__name__}{detail} (fault_id={fault_id})"


class Decision(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK = "block"


@dataclass
class DecisionResult:
    decision: Decision

    triggered_by: str

    reason: str

    capability: str

    agent_id: str

    drift_score: float

    severity: Severity

    invariant_message: str = ""

    advisory_reasons: list[str] = field(default_factory=list)

    evidence: EvidenceReport | None = None

    # Audit set 4 (grant consolidation): the grant under which the
    # authorization level passed. Written into DecisionRecord's
    # schema-reserved approval_ref -- the standing approval this
    # action executed under. None when no authorizer is attached or
    # authorization did not pass via a grant.
    grant_id: str | None = None

    # Audit set 5 (P1-10): the customer-policy rule that fired --
    # written into DecisionRecord's schema-reserved policy_id. None
    # when no policy level is attached, no rule fired, or the backend
    # (OPA) does not expose rule identity.
    policy_id: str | None = None

    # ADR 0020: the digest of the verified, single-use approval artifact
    # that turned REQUIRE_APPROVAL into this ALLOW. Written into
    # DecisionRecord.approval_ref ahead of grant_id. None otherwise.
    approval_artifact_digest: str | None = None

    def to_dict(self):

        return {
            "decision": self.decision.value,
            "triggered_by": self.triggered_by,
            "reason": self.reason,
            "capability": self.capability,
            "agent_id": self.agent_id,
            "drift_score": self.drift_score,
            "severity": self.severity.value,
            "invariant_message": self.invariant_message,
            "advisory_reasons": self.advisory_reasons,
            "evidence": (
                [
                    {
                        "name": i.name,
                        "score": i.score,
                        "confidence": i.confidence,
                        "summary": i.summary,
                    }
                    for i in self.evidence.items
                ]
                if self.evidence is not None
                else []
            ),
            "evidence_strength": (
                self.evidence.overall_strength if self.evidence is not None else 0.0
            ),
        }


@runtime_checkable
class InvariantResultLike(Protocol):
    violated: bool

    message: str


@runtime_checkable
class Authorizer(Protocol):
    def is_authorized(
        self,
        agent_id: str,
        capability: str,
    ) -> bool: ...


@runtime_checkable
class InvariantChecker(Protocol):
    def validate(
        self,
        capability: str,
        previous: str | None,
    ) -> InvariantResultLike: ...


class DecisionEngine:
    def __init__(
        self,
        scorer=None,
        invariants: InvariantChecker | None = None,
        authorizer: Authorizer | None = None,
        drift_threshold: float = 0.50,
        uaal=None,  # optional UAALConstraintChecker (L0)
        economics=None,  # optional CostAnomalyChecker
        consensus=None,  # optional ConsensusChecker
        policy=None,  # optional PolicyChecker (customer YAML/JSON rules)
        approvals=None,  # optional ApprovalBridge (ADR 0020)
    ):

        self.scorer = scorer
        self.approvals = approvals

        self.invariants = invariants

        self.authorizer = authorizer

        self.drift_threshold = drift_threshold

        self.uaal = uaal
        self.economics = economics
        self.consensus = consensus
        self.policy = policy

        self.evidence_engine = EvidenceEngine()

    def decide_from(  # noqa: C901
        self,
        *,
        signal: AdvisorySignal,
        invariant: InvariantResultLike | None = None,
        authorized: bool = True,
        evidence: dict | None = None,
        arguments: dict | None = None,
        grant_id: str | None = None,
    ) -> DecisionResult:

        capability = signal.capability
        agent_id = signal.agent_id

        def make(
            decision: Decision,
            triggered_by: str,
            reason: str,
            policy_id: str | None = None,
        ) -> DecisionResult:

            return DecisionResult(
                decision=decision,
                triggered_by=triggered_by,
                reason=reason,
                grant_id=grant_id,
                policy_id=policy_id,
                capability=capability,
                agent_id=agent_id,
                drift_score=signal.drift_score,
                severity=signal.severity,
                invariant_message=(invariant.message if invariant is not None else ""),
                advisory_reasons=list(signal.reasons),
                evidence=self.evidence_engine.build(
                    drift_score=signal.drift_score,
                    invariant=(invariant is not None and invariant.violated),
                    authorized=authorized,
                ),
            )

        #
        # 1. Deterministic behavioral contracts always win.
        #

        if invariant is not None and invariant.violated:
            return make(
                Decision.BLOCK,
                "invariant",
                invariant.message,
            )
        #
        # 1.4. Customer policy -- data-driven rules (YAML/JSON), not
        # hardcoded Python. Evidence-gated per-rule: a rule whose
        # condition field is absent is skipped, never silently
        # matched or non-matched. UNLIKE every other level, this
        # level's OUTCOME is data-driven: the matched rule declares
        # whether it blocks or requires approval -- the one
        # asymmetry in the precedence chain.
        #
        if self.policy is not None:
            pol = self.policy.check(
                agent_id=agent_id,
                capability=capability,
                arguments=arguments,
                evidence=evidence,
            )
            if pol.fired:
                pol_decision = (
                    Decision.BLOCK
                    if pol.outcome == "block"
                    else Decision.REQUIRE_APPROVAL
                )
                return make(
                    pol_decision,
                    "policy",
                    pol.reason,
                    policy_id=getattr(pol, "matched_rule_id", None),
                )

        #
        # 1.5. Consensus — multi-agent quorum, when evidence is
        # supplied. Evidence-gated: absent evidence means SKIPPED,
        # never silently passed. Never BLOCKs; a quorum shortfall is
        # a governance signal, not a proven security violation.
        #

        if self.consensus is not None:
            con = self.consensus.check(evidence=evidence)
            if con.flagged:
                return make(
                    Decision.REQUIRE_APPROVAL,
                    "consensus",
                    con.reason,
                )

        #
        # 2. Unauthorized capability.
        #

        if not authorized:
            return make(
                Decision.REQUIRE_APPROVAL,
                "authorization",
                (f"Capability '{capability}' is not covered by an approved grant."),
            )

        #
        # 2.5. Economics — cost anomaly / ROI floor. Deterministic,
        # never BLOCKs; ceiling is REQUIRE_APPROVAL, same as
        # authorization and drift.
        #

        if self.economics is not None:
            econ = self.economics.check(evidence=evidence)
            if econ.flagged:
                return make(
                    Decision.REQUIRE_APPROVAL,
                    "economics",
                    "; ".join(econ.reasons),
                )

        #
        # 3. Learned behavioral drift.
        #

        if signal.drift_score >= self.drift_threshold:
            return make(
                Decision.REQUIRE_APPROVAL,
                "drift",
                (f"Behavioral drift {signal.drift_score:.2f}"),
            )

        #
        # 4. Normal behavior.
        #

        return make(
            Decision.ALLOW,
            "baseline",
            "Behavior matches trusted profile.",
        )

    def decide(
        self,
        action: AgentAction,
        prev_capability: str | None = None,
        evidence: dict | None = None,
        *,
        approval=None,
        approval_context=None,
    ) -> DecisionResult:
        try:
            result = self._decide_unsafe(action, prev_capability, evidence)
            if approval is not None:
                result = self._apply_approval(
                    action, result, approval, approval_context
                )
            return result
        except Exception as exc:
            #
            # Fail-closed: ANY exception inside the decision path — a
            # buggy scorer, invariant checker, authorizer, or UAAL
            # evidence source — must never propagate (denial of
            # enforcement) and must never be silently swallowed into
            # an ALLOW. The fault itself becomes an auditable BLOCK.
            #
            return DecisionResult(
                decision=Decision.BLOCK,
                triggered_by="engine_fault",
                reason=fault_reason(exc),
                capability=action.capability,
                agent_id=action.agent_id,
                drift_score=0.0,
                severity=Severity.CRITICAL,
                invariant_message="",
                advisory_reasons=[],
                evidence=self.evidence_engine.build(
                    drift_score=0.0,
                    invariant=True,
                    authorized=True,
                ),
            )

    def _apply_approval(
        self,
        action: AgentAction,
        result: DecisionResult,
        approval,
        approval_context,
    ) -> DecisionResult:
        """ADR 0020: let a verified, single-use approval satisfy a
        REQUIRE_APPROVAL that came from policy or authorization.

        Anything else leaves the verdict untouched: BLOCK stays BLOCK, a
        plain ALLOW does not consume the approval, drift and consensus and
        economics escalations are not human-approvable here. A refused
        approval is recorded in the reason and never changes the verdict.
        """
        from agent_dna.approval_bridge import (
            APPROVABLE_TRIGGERS,
            APPROVAL_NOT_CONFIGURED,
            TRIGGERED_BY_APPROVAL,
            ApprovalContext,
        )

        if result.decision is not Decision.REQUIRE_APPROVAL:
            return result
        if result.triggered_by not in APPROVABLE_TRIGGERS:
            result.reason += (
                f"; approval refused: {result.triggered_by} escalations "
                "are not satisfiable by an approval"
            )
            return result
        if self.approvals is None:
            result.reason += (
                f"; approval refused: {APPROVAL_NOT_CONFIGURED}: no approver "
                "trust bundle is pinned"
            )
            return result
        if not isinstance(approval_context, ApprovalContext):
            result.reason += (
                "; approval refused: APPROVAL_MALFORMED: no approval context"
            )
            return result
        verdict = self.approvals.consider(
            approval, context=approval_context, agent_id=action.agent_id
        )
        if not verdict.ok:
            result.reason += "; " + verdict.refusal
            return result
        return DecisionResult(
            decision=Decision.ALLOW,
            triggered_by=TRIGGERED_BY_APPROVAL,
            reason=f"{verdict.detail}; satisfied: {result.reason}",
            capability=result.capability,
            agent_id=result.agent_id,
            drift_score=result.drift_score,
            severity=result.severity,
            invariant_message=result.invariant_message,
            advisory_reasons=list(result.advisory_reasons),
            evidence=self.evidence_engine.build(
                drift_score=result.drift_score,
                invariant=False,
                authorized=True,
            ),
            grant_id=None,
            policy_id=result.policy_id,
            approval_artifact_digest=verdict.artifact_digest,
        )

    def _decide_unsafe(  # noqa: C901
        self,
        action: AgentAction,
        prev_capability: str | None = None,
        evidence: dict | None = None,
    ) -> DecisionResult:

        if self.scorer is not None:
            signal = self.scorer.score(
                action,
                prev_capability,
            )
        else:
            # Drift (L5) is inert when no scorer is attached. This is a
            # supported configuration -- decide_from() callers supply their
            # own signal, and scan/replay deliberately constructs with
            # scorer=None -- but an unattached layer must never read as
            # "no drift detected". The inertness travels with every
            # decision through advisory_reasons, so no record can imply
            # drift was evaluated when it was not.
            from .advisory import AdvisorySignal, Posture

            signal = AdvisorySignal(
                agent_id=action.agent_id,
                capability=action.capability,
                drift_score=0.0,
                severity=Severity.INFO,
                components={},
                reasons=["drift inert: no scorer attached (L5 not evaluated)"],
                recommended_posture=Posture.LOG,
            )

        #
        # 0. UAAL enterprise constraints — above everything.
        #
        if self.uaal is not None:
            u = self.uaal.check(action, evidence)
            if u.violated:
                return DecisionResult(
                    decision=Decision.BLOCK,
                    triggered_by="uaal_constraint",
                    reason=u.message,
                    capability=action.capability,
                    agent_id=action.agent_id,
                    drift_score=signal.drift_score,
                    severity=signal.severity,
                    invariant_message=u.message,
                    advisory_reasons=list(signal.reasons),
                    evidence=self.evidence_engine.build(
                        drift_score=signal.drift_score,
                        invariant=True,
                        authorized=True,
                    ),
                )

        invariant = None

        if self.invariants is not None:
            invariant = self.invariants.validate(
                action.capability,
                prev_capability,
            )

        authorized = False
        auth_reason = None
        grant_id = None

        if self.authorizer is None:
            # Absence is a configuration error, never an implicit allow.
            from agent_dna.control_posture import AUTHORIZATION_NOT_CONFIGURED

            authorized = False
            auth_reason = (
                f"{AUTHORIZATION_NOT_CONFIGURED}: authorization layer "
                "not configured (fail-closed); attach GrantRegistry or "
                "OpenAuthorizer"
            )
        elif hasattr(self.authorizer, "explain"):
            raw_amount = (action.arguments or {}).get("amount")
            amount = None
            if raw_amount is not None:
                try:
                    amount = coerce_amount(raw_amount)
                except InvalidAmountError:
                    return DecisionResult(
                        decision=Decision.BLOCK,
                        triggered_by="authorization",
                        reason=INVALID_AMOUNT_REASON,
                        capability=action.capability,
                        agent_id=action.agent_id,
                        drift_score=signal.drift_score,
                        severity=Severity.CRITICAL,
                        invariant_message="",
                        advisory_reasons=list(signal.reasons),
                        evidence=self.evidence_engine.build(
                            drift_score=signal.drift_score,
                            invariant=True,
                            authorized=False,
                        ),
                    )
            authorized, auth_reason, grant_id = self.authorizer.explain(
                action.agent_id,
                action.capability,
                amount=amount,
            )
            if (
                not authorized
                and auth_reason is not None
                and INVALID_AMOUNT in auth_reason
            ):
                return DecisionResult(
                    decision=Decision.BLOCK,
                    triggered_by="authorization",
                    reason=auth_reason,
                    capability=action.capability,
                    agent_id=action.agent_id,
                    drift_score=signal.drift_score,
                    severity=Severity.CRITICAL,
                    invariant_message="",
                    advisory_reasons=list(signal.reasons),
                    evidence=self.evidence_engine.build(
                        drift_score=signal.drift_score,
                        invariant=True,
                        authorized=False,
                    ),
                )
        else:
            authorized = self.authorizer.is_authorized(
                action.agent_id, action.capability
            )

        merged_evidence = dict(action.evidence or {})
        if evidence is not None:
            merged_evidence.update(evidence)
        result = self.decide_from(
            signal=signal,
            invariant=invariant,
            authorized=authorized,
            evidence=merged_evidence,
            arguments=action.arguments,
            grant_id=grant_id,
        )
        if auth_reason is not None and result.triggered_by == "authorization":
            result.reason = auth_reason
        return result
