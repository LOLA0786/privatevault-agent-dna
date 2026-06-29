"""
Evidence Engine.

Produces structured evidence explaining WHY a runtime decision was made.
This layer is explainability only. It performs no detection and makes no
enforcement decisions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class EvidenceItem:
    name: str
    score: float
    confidence: float
    summary: str


@dataclass
class EvidenceReport:
    items: List[EvidenceItem] = field(default_factory=list)

    @property
    def overall_strength(self) -> float:

        if not self.items:
            return 0.0

        return sum(
            i.score * i.confidence
            for i in self.items
        ) / len(self.items)

    def add(
        self,
        item: EvidenceItem,
    ) -> None:

        self.items.append(item)


class EvidenceEngine:
    """
    Collects evidence from multiple runtime signals.

    This class never decides ALLOW/BLOCK.
    It only explains WHY another component reached that decision.
    """

    def build(
        self,
        *,
        drift_score: float,
        invariant: bool,
        authorized: bool,
        confidence: float = 1.0,
    ) -> EvidenceReport:

        report = EvidenceReport()

        #
        # Drift
        #

        if drift_score > 0.0:

            report.add(
                EvidenceItem(
                    name="Behavioral Drift",
                    score=drift_score,
                    confidence=confidence,
                    summary=(
                        f"Runtime drift score {drift_score:.2f}"
                    ),
                )
            )

        #
        # Invariants
        #

        if invariant:

            report.add(
                EvidenceItem(
                    name="Behavioral Invariant",
                    score=1.0,
                    confidence=1.0,
                    summary="Behavioral contract violated.",
                )
            )

        #
        # Authorization
        #

        if not authorized:

            report.add(
                EvidenceItem(
                    name="Authorization",
                    score=1.0,
                    confidence=1.0,
                    summary="Capability has no approved grant.",
                )
            )

        return report
