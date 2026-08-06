"""Topology invariant: *which agent is allowed to talk to which agent*.

Learns the set of edges ever observed across known-good executions, plus the
edges that are effectively mandatory (present in nearly every execution).

  - A novel edge (never seen in training) is a SOFT signal -> drives REVIEW,
    and BLOCK only if several pile up. Rationale: an unseen wiring is
    suspicious but not, on its own, proof of compromise.
  - A missing mandatory edge is a softer signal still (an expected control
    step was skipped) -> REVIEW.

Authority-level "marketing must never pay" lives in :mod:`authority`; this
module is about concrete agent wiring.
"""

from __future__ import annotations

from collections import Counter

from .base import Invariant, InvariantResult
from .interaction_graph import InteractionGraph


class TopologyInvariant(Invariant):
    name = "topology"

    def __init__(
        self,
        mandatory_threshold: float = 0.95,
        novel_weight: float = 0.45,
        missing_weight: float = 0.30,
    ) -> None:
        self.mandatory_threshold = mandatory_threshold
        self.novel_weight = novel_weight
        self.missing_weight = missing_weight
        self.allowed_edges: set[tuple[str, str]] = set()
        self.mandatory_edges: set[tuple[str, str]] = set()
        self.edge_support: dict[tuple[str, str], float] = {}
        self.n_executions = 0

    def learn(self, graphs: list[InteractionGraph]) -> None:
        self.n_executions = len(graphs)
        if not graphs:
            return
        counts: Counter[tuple[str, str]] = Counter()
        for g in graphs:
            for edge in g.edges:  # set per graph -> counts executions
                counts[edge] += 1
        self.allowed_edges = set(counts)
        self.edge_support = {e: c / self.n_executions for e, c in counts.items()}
        self.mandatory_edges = {
            e
            for e, support in self.edge_support.items()
            if support >= self.mandatory_threshold
        }

    def check(self, graph: InteractionGraph) -> InvariantResult:
        novel = sorted(graph.edges - self.allowed_edges)
        missing = sorted(self.mandatory_edges - graph.edges)

        violations: list[str] = []
        for s, t in novel:
            violations.append(f"novel edge {s} -> {t} never seen in training")
        for s, t in missing:
            violations.append(f"mandatory edge {s} -> {t} missing from execution")

        severity = min(
            1.0, self.novel_weight * len(novel) + self.missing_weight * len(missing)
        )
        passed = not novel and not missing
        return InvariantResult(
            name=self.name,
            passed=passed,
            severity=severity,
            hard=False,  # topology alone never hard-blocks
            violations=violations,
        )

    def describe(self) -> dict:
        return {
            "name": self.name,
            "allowed_edges": len(self.allowed_edges),
            "mandatory_edges": len(self.mandatory_edges),
            "n_executions": self.n_executions,
        }
