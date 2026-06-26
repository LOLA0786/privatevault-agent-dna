"""
The advisory / enforcement boundary.

This module encodes the single most important property in the Agent DNA research
vision: *the learned model is advisory only and never replaces policy
enforcement.* We make that a code-level invariant, not a slogan.

An `AdvisorySignal` carries a drift score, a severity, decomposed evidence, and a
*recommended* posture. It cannot, by itself, allow or deny anything. The
`DeterministicGate` is what produces an authoritative decision, and it obeys two
rules:

  1. The deterministic policy decision is authoritative for ALLOW vs DENY.
     Agent DNA can never turn a policy DENY into an ALLOW.
  2. Agent DNA can only *raise* scrutiny, never lower it: it may escalate an
     allowed action to "require human approval", but it can never downgrade a
     required approval to an automatic allow.

This is also a selling point with regulated buyers: the security boundary stays
deterministic and auditable; the ML adds earlier warning, not a new bypass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List


class Severity(str, Enum):
    INFO = "info"
    ELEVATED = "elevated"
    CRITICAL = "critical"


class Posture(str, Enum):
    LOG = "log"
    REQUIRE_APPROVAL = "require_approval"
    RECOMMEND_BLOCK = "recommend_block"


@dataclass
class AdvisorySignal:
    agent_id: str
    capability: str
    drift_score: float  # 0.0 .. 1.0
    severity: Severity
    components: Dict[str, float] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)
    recommended_posture: Posture = Posture.LOG

    def to_dict(self) -> Dict:
        return {
            "agent_id": self.agent_id,
            "capability": self.capability,
            "drift_score": round(self.drift_score, 4),
            "severity": self.severity.value,
            "components": {k: round(v, 4) for k, v in self.components.items()},
            "reasons": self.reasons,
            "recommended_posture": self.recommended_posture.value,
        }


# ---- enforcement boundary -----------------------------------------------

class PolicyDecision(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


@dataclass
class GateDecision:
    decision: PolicyDecision
    authoritative_source: str  # "policy" or "policy+advisory"
    advisory: AdvisorySignal
    rationale: str


class DeterministicGate:
    """
    Combines an authoritative deterministic policy decision with an Agent DNA
    advisory signal. The deterministic decision wins; the advisory may only
    raise scrutiny.
    """

    def decide(
        self,
        policy_decision: PolicyDecision,
        advisory: AdvisorySignal,
    ) -> GateDecision:
        # Rule 1: a policy DENY is final. Advisory cannot relax it.
        if policy_decision == PolicyDecision.DENY:
            return GateDecision(
                decision=PolicyDecision.DENY,
                authoritative_source="policy",
                advisory=advisory,
                rationale="Policy denied; advisory cannot override a deterministic deny.",
            )

        # Rule 2: advisory may only escalate, never relax.
        if advisory.recommended_posture in (
            Posture.RECOMMEND_BLOCK,
            Posture.REQUIRE_APPROVAL,
        ):
            if policy_decision == PolicyDecision.ALLOW:
                return GateDecision(
                    decision=PolicyDecision.REQUIRE_APPROVAL,
                    authoritative_source="policy+advisory",
                    advisory=advisory,
                    rationale=(
                        "Policy allowed, but Agent DNA flagged behavioural drift "
                        f"({advisory.severity.value}); escalated to human approval."
                    ),
                )

            # already require_approval -> stays require_approval
            return GateDecision(
                decision=PolicyDecision.REQUIRE_APPROVAL,
                authoritative_source="policy+advisory",
                advisory=advisory,
                rationale="Policy required approval; advisory concurs.",
            )

        # Advisory is quiet -> deterministic decision passes through unchanged.
        return GateDecision(
            decision=policy_decision,
            authoritative_source="policy",
            advisory=advisory,
            rationale="Advisory within trusted profile; policy decision unchanged.",
        )
