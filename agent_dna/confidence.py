"""
Behavior Profile Confidence.

Measures how trustworthy a learned behavioral profile is based on the
amount of observed behavior.
"""

from __future__ import annotations

from dataclasses import dataclass

from .manifold import CapabilityManifold


@dataclass
class ConfidenceScore:
    score: float          # 0..1
    level: str            # LOW / MEDIUM / HIGH
    training_actions: int
    rationale: str


class ConfidenceEstimator:

    LOW_THRESHOLD = 100
    HIGH_THRESHOLD = 1000

    def estimate(
        self,
        manifold: CapabilityManifold,
    ) -> ConfidenceScore:

        n = manifold.total_actions

        if n < self.LOW_THRESHOLD:
            return ConfidenceScore(
                score=n / self.LOW_THRESHOLD,
                level="LOW",
                training_actions=n,
                rationale="Profile still learning; collect more trusted executions.",
            )

        if n < self.HIGH_THRESHOLD:
            score = min(
                1.0,
                n / self.HIGH_THRESHOLD,
            )

            return ConfidenceScore(
                score=score,
                level="MEDIUM",
                training_actions=n,
                rationale="Profile is reasonably stable but additional history will improve reliability.",
            )

        return ConfidenceScore(
            score=1.0,
            level="HIGH",
            training_actions=n,
            rationale="Profile has sufficient behavioral history for high-confidence comparisons.",
        )
