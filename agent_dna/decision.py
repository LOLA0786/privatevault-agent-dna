"""
Unified Runtime Decision Engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, runtime_checkable

from .advisory import AdvisorySignal, Severity
from .evidence import EvidenceEngine, EvidenceReport
from .trace import AgentAction


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
    ):

        self.scorer = scorer

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
    ) -> DecisionResult:
        try:
            return self._decide_unsafe(action, prev_capability, evidence)
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
                reason=f"{type(exc).__name__}: {exc}",
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

    def _decide_unsafe(  # noqa: C901
        self,
        action: AgentAction,
        prev_capability: str | None = None,
        evidence: dict | None = None,
    ) -> DecisionResult:

        signal = self.scorer.score(
            action,
            prev_capability,
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
            malformed = False
            if raw_amount is not None:
                try:
                    amount = float(raw_amount)
                except (TypeError, ValueError):
                    # Audit set 4: a garbage amount used to coerce
                    # to None, silently SKIPPING the budget check
                    # on a budgeted grant -- malformed input must
                    # never widen authorization.
                    malformed = True
            if malformed:
                authorized, auth_reason, grant_id = (
                    False,
                    f"malformed amount {raw_amount!r}: budget cannot "
                    "be evaluated (fail-closed)",
                    None,
                )
            else:
                authorized, auth_reason, grant_id = self.authorizer.explain(
                    action.agent_id,
                    action.capability,
                    amount=amount,
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
