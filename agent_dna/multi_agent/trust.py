"""Trust-score invariants for directed agent interactions.

Trust is captured on :class:`InteractionEvent` at the moment the source agent
acts.  The invariant learns the lowest known-good score for each directed
agent pair, then detects material degradation without inventing trust for
pairs that were absent from the training corpus.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from .base import Invariant, InvariantResult
from .interaction_graph import InteractionGraph


@dataclass(slots=True)
class TrustResult:
    """Compatibility result returned by :meth:`TrustInvariant.validate`."""

    severity: float
    reasons: list[str]
    hard: bool = False


class TrustInvariant(Invariant):
    """Detect trust degradation on previously observed directed edges.

    ``review_margin`` and ``block_margin`` are absolute drops from the
    minimum score seen for a pair in the known-good corpus.  Invalid scores
    are rejected during learning and are hard failures during evaluation.
    """

    name = "trust"

    def __init__(self, review_margin: float = 0.10, block_margin: float = 0.30):
        if not 0.0 <= review_margin <= block_margin <= 1.0:
            raise ValueError(
                "trust margins must satisfy 0 <= review_margin <= block_margin <= 1"
            )
        self.review_margin = review_margin
        self.block_margin = block_margin
        self.minimum_trust: dict[tuple[str, str], float] = {}

    def learn(self, graphs: list[InteractionGraph]) -> None:
        values: defaultdict[tuple[str, str], list[float]] = defaultdict(list)
        for graph in graphs:
            for event in graph.events:
                if not 0.0 <= event.trust <= 1.0:
                    raise ValueError(
                        f"invalid trust score {event.trust!r} for "
                        f"{event.source!r} -> {event.target!r}"
                    )
                values[event.edge()].append(event.trust)

        self.minimum_trust = {pair: min(scores) for pair, scores in values.items()}

    # Retained for callers of the pre-InvariantEngine API.
    fit = learn

    def validate(self, graph: InteractionGraph) -> TrustResult:
        severity = 0.0
        reasons: list[str] = []
        hard = False

        for event in graph.events:
            pair = event.edge()
            if not 0.0 <= event.trust <= 1.0:
                hard = True
                severity = 1.0
                reasons.append(
                    f"invalid trust score for {event.source} -> {event.target}: "
                    f"{event.trust!r}"
                )
                continue

            expected = self.minimum_trust.get(pair)
            if expected is None:
                continue

            delta = expected - event.trust
            if delta >= self.block_margin:
                hard = True
                severity = 1.0
                reasons.append(
                    f"trust breach: {event.source} -> {event.target} "
                    f"(expected >= {expected:.2f}, observed {event.trust:.2f})"
                )
            elif delta >= self.review_margin:
                severity = max(severity, 0.40)
                reasons.append(
                    f"trust degradation: {event.source} -> {event.target} "
                    f"(expected >= {expected:.2f}, observed {event.trust:.2f})"
                )

        return TrustResult(severity=severity, reasons=reasons, hard=hard)

    def check(self, graph: InteractionGraph) -> InvariantResult:
        result = self.validate(graph)
        return InvariantResult(
            name=self.name,
            passed=not result.reasons,
            severity=result.severity,
            hard=result.hard,
            violations=result.reasons,
        )

    def describe(self) -> dict[str, object]:
        return {
            "name": self.name,
            "trusted_edges": len(self.minimum_trust),
            "review_margin": self.review_margin,
            "block_margin": self.block_margin,
        }
