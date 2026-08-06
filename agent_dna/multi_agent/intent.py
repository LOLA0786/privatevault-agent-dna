"""Intent Behavioral Invariant."""

from __future__ import annotations

from collections import defaultdict

from .base import Invariant, InvariantResult
from .interaction_graph import InteractionGraph


class IntentInvariant(Invariant):
    """Learns valid intents for each role."""

    name = "intent"

    def __init__(self) -> None:
        self.allowed: dict[str, set[str]] = defaultdict(set)

    def learn(self, graphs: list[InteractionGraph]) -> None:
        self.allowed.clear()

        for graph in graphs:
            for event in graph:
                if event.intent:
                    self.allowed[event.source_role].add(event.intent.strip().lower())

    def check(self, graph: InteractionGraph) -> InvariantResult:
        violations: list[str] = []
        total = 0

        for event in graph:
            if not event.intent:
                continue

            total += 1

            known = self.allowed.get(event.source_role)

            if not known:
                continue

            intent = event.intent.strip().lower()

            if intent not in known:
                violations.append(
                    f'role "{event.source_role}" issued unseen intent "{event.intent}"'
                )

        severity = len(violations) / max(1, total)

        return InvariantResult(
            name=self.name,
            passed=not violations,
            severity=severity,
            hard=False,
            violations=violations,
        )

    def describe(self) -> dict:
        return {
            "name": self.name,
            "roles": len(self.allowed),
        }
