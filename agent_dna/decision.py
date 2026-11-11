"""
Unified Runtime Decision Engine.
"""

from __future__ import annotations

import inspect
import logging
import os
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

NO_GRANT_PREFIX = "no grant exists"
UNGRANTED_DECISION_ENV = "PV_UNGRANTED_DECISION"


def ungranted_decision() -> str:
    """'block' or 'require_approval' for a capability with no grant at all.

    Default: block under PV_SECURE_PROFILE, require_approval otherwise.
    An unrecognised value fails closed to block.
    """
    raw = os.environ.get(UNGRANTED_DECISION_ENV, "").strip().lower()
    if not raw:
        secure = os.environ.get("PV_SECURE_PROFILE", "0").lower()
        return "block" if secure in ("1", "true", "yes", "on") else "require_approval"
    return raw if raw in ("block", "require_approval") else "block"


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

    # Levels that fired in addition to triggered_by: the level under a
    # customer-policy hold, or the level an ungranted BLOCK overrode. An
    # approval may lift a hold only if every one of them is approvable.
    also_fired: list[str] = field(default_factory=list)

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
    def _drift_hint(self, capability: str) -> str:
        base = self.baseline_capabilities
        if base is None or capability in base:
            return ""
        return (
            f"; capability '{capability}' is not in PV_BASELINE_CAPABILITIES "
            "(the drift baseline). A grant authorizes it, but drift review still "
            "holds unfamiliar use; add it to PV_BASELINE_CAPABILITIES to treat "
            "it as normal"
        )

    def __init__(
        self,
        scorer=None,
        invariants: InvariantChecker | None = None,
        authorizer: Authorizer | None = None,
        drift_threshold: float = 0.50,
        uaal=None,  # optional UAALConstraintChecker (L0)
        economics=None,  # optional CostAnomalyChecker
        consensus=None,  # optional ConsensusChecker
        delegation=None,  # optional multi_agent_security.DelegationGate
        policy=None,  # optional PolicyChecker (customer YAML/JSON rules)
        approvals=None,  # optional ApprovalBridge (ADR 0020)
    ):

        self.scorer = scorer
        self.approvals = approvals

        self.invariants = invariants

        self.authorizer = authorizer

        self.drift_threshold = drift_threshold
        # Capabilities trained into the drift baseline (PV_BASELINE_CAPABILITIES);
        # only used to explain a drift hold. None = not reported.
        self.baseline_capabilities: frozenset[str] | None = None

        self.uaal = uaal
        self.economics = economics
        self.consensus = consensus
        # Restricts authorization only: a chain never grants what the
        # agent's own grant does not.
        self.delegation = delegation
        # Checkers written before votes were bound to the action take only
        # ``evidence``; ConsensusChecker also takes the action under decision.
        self._consensus_binds_action = False
        if consensus is not None:
            try:
                names = set(inspect.signature(consensus.check).parameters)
            except (TypeError, ValueError):
                names = set()
            self._consensus_binds_action = {
                "agent_id",
                "capability",
                "arguments",
            } <= names
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
        # A policy BLOCK is final and returns here. A policy
        # REQUIRE_APPROVAL is ADDITIVE: the levels below still run, and
        # the verdict is the stricter of the two. It used to return
        # first, so the levels under it never ran -- and because a policy
        # hold is approvable, adding a rule like "large payments need
        # sign-off" let an approval lift a hold that drift, economics or
        # consensus would have made non-approvable, and skipped the
        # secure profile's ungranted BLOCK. Adding a rule must never make
        # an action easier to run.
        #
        policy_hold: DecisionResult | None = None
        if self.policy is not None:
            pol = self.policy.check(
                agent_id=agent_id,
                capability=capability,
                arguments=arguments,
                evidence=evidence,
            )
            if pol.fired:
                rule_id = getattr(pol, "matched_rule_id", None)
                if pol.outcome == "block":
                    return make(Decision.BLOCK, "policy", pol.reason, policy_id=rule_id)
                policy_hold = make(
                    Decision.REQUIRE_APPROVAL, "policy", pol.reason, policy_id=rule_id
                )

        def below_policy() -> DecisionResult:
            #
            # 1.5. Consensus — multi-agent quorum. Evidence-gated: absent
            # evidence means SKIPPED (or a hold where the operator requires
            # a quorum), never silently passed. Never BLOCKs; a quorum shortfall is
            # a governance signal, not a proven security violation.
            #

            if self.consensus is not None:
                if self._consensus_binds_action:
                    con = self.consensus.check(
                        evidence=evidence,
                        agent_id=agent_id,
                        capability=capability,
                        arguments=arguments,
                    )
                else:
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
                    (f"Behavioral drift {signal.drift_score:.2f}")
                    + self._drift_hint(capability),
                )

            #
            # 4. Normal behavior.
            #

            return make(
                Decision.ALLOW,
                "baseline",
                "Behavior matches trusted profile.",
            )

        lower = below_policy()
        if policy_hold is None:
            return lower
        if lower.decision is Decision.ALLOW:
            return policy_hold
        # Both the rule and a level under it fired. The rule names the
        # verdict; the lower level travels with it, so the record shows it
        # and _apply_approval can refuse when it is not approvable.
        policy_hold.also_fired = [lower.triggered_by]
        policy_hold.reason += f"; also held by {lower.triggered_by}: {lower.reason}"
        return policy_hold

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
        blocking = [
            trigger
            for trigger in (result.triggered_by, *result.also_fired)
            if trigger not in APPROVABLE_TRIGGERS
        ]
        if blocking:
            result.reason += (
                f"; approval refused: {', '.join(blocking)} escalations "
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
            approval,
            context=approval_context,
            agent_id=action.agent_id,
            capability=action.capability,
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

        # Delegation (multi-agent security layer). Part of the authorization
        # level: it can only take authorization away. A refusal is a BLOCK
        # (applied below, after the ladder has run).
        delegation = None
        if self.delegation is not None:
            delegated_amount: float | None = None
            raw_delegated = (action.arguments or {}).get("amount")
            if raw_delegated is not None:
                try:
                    delegated_amount = float(coerce_amount(raw_delegated))
                except InvalidAmountError:
                    delegated_amount = float("nan")  # refused by the gate
            delegation = self.delegation.check(
                agent_id=action.agent_id,
                capability=action.capability,
                arguments=action.arguments,
                amount=delegated_amount,
                evidence=merged_evidence,
            )
            if delegation.refused:
                if authorized or auth_reason is None:
                    auth_reason = delegation.reason
                authorized = False
                grant_id = None

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
        if (
            delegation is not None
            and delegation.checked
            and not delegation.refused
            and result.decision is Decision.ALLOW
        ):
            # Sealed into the signed record: which chain this ran under.
            result.reason += f"; {delegation.reason}"
        if (
            not authorized
            and auth_reason is not None
            and result.decision is Decision.REQUIRE_APPROVAL
            and auth_reason.startswith(NO_GRANT_PREFIX)
            and ungranted_decision() == "block"
        ):
            # No grant at all is not a request to escalate: under the
            # secure profile (or PV_UNGRANTED_DECISION=block) it is a
            # hard refusal that no approval can turn into an ALLOW. That
            # holds whichever level named the hold: a customer-policy rule
            # or a consensus shortfall firing above authorization used to
            # return first and leave this an approvable REQUIRE_APPROVAL.
            if result.triggered_by != "authorization":
                result.also_fired = [result.triggered_by]
                result.reason = f"{auth_reason}; also held by {result.triggered_by}"
                result.triggered_by = "authorization"
            result.decision = Decision.BLOCK
            result.severity = Severity.CRITICAL
        if delegation is not None and delegation.refused:
            # A missing, forged, out-of-scope or replayed delegation is a
            # hard refusal, like an invalid amount. As a hold it could not
            # be approved through the approval bridge either, but an
            # interactive client would still have shown it as a question
            # its user could answer "allow".
            others = [
                trigger
                for trigger in (result.triggered_by, *result.also_fired)
                if trigger not in ("authorization", "delegation")
            ]
            result.decision = Decision.BLOCK
            result.severity = Severity.CRITICAL
            result.triggered_by = "authorization"
            result.also_fired = ["delegation", *others]
            result.reason = delegation.reason + (
                "; also held by " + ", ".join(others) if others else ""
            )
        return result
