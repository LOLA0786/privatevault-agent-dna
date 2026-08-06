"""
Behavioral Invariants.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from .trace import ExecutionTrace


@dataclass
class BehavioralInvariant:
    capability: str
    allowed_predecessors: set[str]


class InvariantLearner:
    def fit(
        self,
        traces: list[ExecutionTrace],
    ) -> dict[str, BehavioralInvariant]:

        predecessors = defaultdict(set)

        for trace in traces:
            previous = "__START__"

            for action in trace.actions:
                predecessors[action.capability].add(previous)

                previous = action.capability

        invariants = {}

        for capability, preds in predecessors.items():
            invariants[capability] = BehavioralInvariant(
                capability=capability,
                allowed_predecessors=preds,
            )

        return invariants
