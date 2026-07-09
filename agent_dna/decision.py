"""
Unified Runtime Decision Engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Protocol, runtime_checkable

from .advisory import AdvisorySignal, Severity
from .trace import AgentAction
from .evidence import EvidenceReport, EvidenceEngine


class Decision(str, Enum):
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

    advisory_reasons: List[str] = field(default_factory=list)

    evidence: EvidenceReport | None = None

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
                self.evidence.overall_strength
                if self.evidence is not None
                else 0.0
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
        previous: Optional[str],
    ) -> InvariantResultLike: ...


class DecisionEngine:

    def __init__(
        self,
        scorer=None,
        invariants: Optional[InvariantChecker] = None,
        authorizer: Optional[Authorizer] = None,
        drift_threshold: float = 0.50,
        uaal=None,                     # optional UAALConstraintChecker (L0)
        economics=None,                # optional CostAnomalyChecker (new level)
    ):

        self.scorer = scorer

        self.invariants = invariants

        self.authorizer = authorizer

        self.drift_threshold = drift_threshold

        self.uaal = uaal
        self.economics = economics

        self.evidence_engine = EvidenceEngine()

    def decide_from(
        self,
        *,
        signal: AdvisorySignal,
        invariant: Optional[InvariantResultLike] = None,
        authorized: bool = True,
        evidence: Optional[dict] = None,
    ) -> DecisionResult:

        capability = signal.capability
        agent_id = signal.agent_id

        def make(
            decision: Decision,
            triggered_by: str,
            reason: str,
        ) -> DecisionResult:

            return DecisionResult(
                decision=decision,
                triggered_by=triggered_by,
                reason=reason,
                capability=capability,
                agent_id=agent_id,
                drift_score=signal.drift_score,
                severity=signal.severity,
                invariant_message=(
                    invariant.message
                    if invariant is not None
                    else ""
                ),
                advisory_reasons=list(signal.reasons),
                evidence=self.evidence_engine.build(
                    drift_score=signal.drift_score,
                    invariant=(
                        invariant is not None
                        and
                        invariant.violated
                    ),
                    authorized=authorized,
                ),
            )

        #
        # 1. Deterministic behavioral contracts always win.
        #

        if (
            invariant is not None
            and
            invariant.violated
        ):

            return make(
                Decision.BLOCK,
                "invariant",
                invariant.message,
            )

        #
        # 2. Unauthorized capability.
        #

        if not authorized:

            return make(
                Decision.REQUIRE_APPROVAL,
                "authorization",
                (
                    f"Capability '{capability}' "
                    "is not covered by an approved grant."
                ),
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
                (
                    f"Behavioral drift "
                    f"{signal.drift_score:.2f}"
                ),
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
        prev_capability: Optional[str] = None,
        evidence: Optional[dict] = None,
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

    def _decide_unsafe(
        self,
        action: AgentAction,
        prev_capability: Optional[str] = None,
        evidence: Optional[dict] = None,
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

        authorized = True
        auth_reason = None

        if self.authorizer is not None:
            if hasattr(self.authorizer, "explain"):
                amount = (action.arguments or {}).get("amount")
                try:
                    amount = float(amount) if amount is not None else None
                except (TypeError, ValueError):
                    amount = None
                authorized, auth_reason, grant_id = self.authorizer.explain(
                    action.agent_id, action.capability, amount=amount
                )
            else:
                authorized = self.authorizer.is_authorized(
                    action.agent_id, action.capability
                )

        result = self.decide_from(
            signal=signal,
            invariant=invariant,
            authorized=authorized,
            evidence=evidence,
        )
        if auth_reason is not None and result.triggered_by == "authorization":
            result.reason = auth_reason
        return result
