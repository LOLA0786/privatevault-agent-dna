"""World-State Behavioral Invariant.

Learns valid organizational state transitions from successful executions.

Unlike topology (who talks to whom), this models the evolution of the
business process itself.
"""

from __future__ import annotations

from collections import Counter

from .base import Invariant, InvariantResult
from .interaction_graph import InteractionGraph


class WorldStateInvariant(Invariant):
    """Learns valid business state transitions."""

    name = "world_state"

    def __init__(self) -> None:
        self.allowed_transitions: set[tuple[str, str]] = set()
        self.n_executions = 0

    @staticmethod
    def _state(event):
        return event.metadata.get("state")

    def learn(self, graphs: list[InteractionGraph]) -> None:
        self.allowed_transitions.clear()
        self.n_executions = len(graphs)

        counter: Counter[tuple[str, str]] = Counter()

        for graph in graphs:
            states = [
                self._state(e)
                for e in graph
                if self._state(e) is not None
            ]

            for a, b in zip(states, states[1:]):
                counter[(a, b)] += 1

        self.allowed_transitions = set(counter)

    def check(self, graph: InteractionGraph) -> InvariantResult:
        states = [
            self._state(e)
            for e in graph
            if self._state(e) is not None
        ]

        violations: list[str] = []

        for a, b in zip(states, states[1:]):
            if (a, b) not in self.allowed_transitions:
                violations.append(
                    f"illegal state transition: {a} -> {b}"
                )

        total = max(1, len(states) - 1)
        severity = len(violations) / total

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
            "transitions": len(self.allowed_transitions),
            "n_executions": self.n_executions,
        }
