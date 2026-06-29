"""Temporal invariant: *order matters*.

Learns, for each pair of roles that co-occur, whether one reliably precedes the
other. ``finance`` before ``payment`` in ~100% of training runs becomes the
invariant ``finance precedes payment``. A run that fires payment before finance
is a clear breach -> HARD -> BLOCK.

Ordering is measured by first-appearance timestamp of each role within an
execution. A minimum support guards against inferring an "invariant" from a
handful of coincidental orderings.
"""
from __future__ import annotations

from collections import defaultdict
from itertools import combinations

from .base import Invariant, InvariantResult
from .interaction_graph import InteractionGraph


class TemporalInvariant(Invariant):
    name = "temporal"

    def __init__(self, order_threshold: float = 0.98,
                min_support: int = 5,
                min_support_frac: float = 0.10) -> None:
        self.order_threshold = order_threshold
        self.min_support = min_support
        self.min_support_frac = min_support_frac
        # (role_a, role_b) present means: role_a must precede role_b
        self.orderings: set[tuple[str, str]] = set()
        self.n_executions = 0

    def learn(self, graphs: list[InteractionGraph]) -> None:
        self.n_executions = len(graphs)
        cooccur: dict[tuple[str, str], int] = defaultdict(int)
        a_before_b: dict[tuple[str, str], int] = defaultdict(int)

        for g in graphs:
            fs = g.role_first_seen()
            roles = [r for r in fs if r != "unknown"]
            for r1, r2 in combinations(sorted(roles), 2):
                cooccur[(r1, r2)] += 1
                if fs[r1] < fs[r2]:
                    a_before_b[(r1, r2)] += 1
                elif fs[r2] < fs[r1]:
                    a_before_b[(r2, r1)] += 1
                # ties: contribute to neither direction

        support_floor = max(self.min_support,
                            int(self.min_support_frac * self.n_executions))
        self.orderings.clear()
        for (r1, r2), n_co in cooccur.items():
            if n_co < support_floor:
                continue
            if a_before_b[(r1, r2)] / n_co >= self.order_threshold:
                self.orderings.add((r1, r2))
            if a_before_b[(r2, r1)] / n_co >= self.order_threshold:
                self.orderings.add((r2, r1))

    def check(self, graph: InteractionGraph) -> InvariantResult:
        violations: list[str] = []
        for before, after in sorted(self.orderings):
            precedes = graph.role_precedes(before, after)
            if precedes is None:
                continue  # one of the roles absent -> ordering vacuously holds
            if precedes is False:
                violations.append(
                    f"temporal breach: {after} occurred before {before} "
                    f"(invariant: {before} must precede {after})"
                )
        passed = not violations
        severity = 0.0 if passed else 1.0
        return InvariantResult(
            name=self.name,
            passed=passed,
            severity=severity,
            hard=bool(violations),     # ordering breach is a hard breach
            violations=violations,
        )

    def describe(self) -> dict:
        return {
            "name": self.name,
            "orderings": sorted(f"{a}<{b}" for a, b in self.orderings),
            "n_executions": self.n_executions,
        }
