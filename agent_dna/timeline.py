"""
Behavior Timeline.

Tracks how an agent's behavioral identity evolves across profile versions.
"""

from __future__ import annotations

from dataclasses import dataclass

from .fingerprint import AgentFingerprint
from .similarity import SimilarityEngine, SimilarityResult


@dataclass
class TimelineEntry:
    version: str
    fingerprint: AgentFingerprint


class BehaviorTimeline:
    def __init__(self) -> None:
        self.entries: list[TimelineEntry] = []

    def add(
        self,
        version: str,
        fingerprint: AgentFingerprint,
    ) -> None:
        self.entries.append(
            TimelineEntry(
                version=version,
                fingerprint=fingerprint,
            )
        )

    def versions(self) -> list[str]:
        return [e.version for e in self.entries]

    def latest(self) -> AgentFingerprint:
        return self.entries[-1].fingerprint

    def compare_adjacent(self) -> list[SimilarityResult]:

        engine = SimilarityEngine()
        results: list[SimilarityResult] = []

        for i in range(1, len(self.entries)):
            results.append(
                engine.compare(
                    self.entries[i - 1].fingerprint,
                    self.entries[i].fingerprint,
                )
            )

        return results

    def stability_score(self) -> float:

        comparisons = self.compare_adjacent()

        if not comparisons:
            return 100.0

        avg = sum(c.overall_similarity for c in comparisons) / len(comparisons)

        return round(avg * 100, 2)
