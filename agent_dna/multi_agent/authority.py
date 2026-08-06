"""Authority invariant: *who is allowed to influence whom*, at the role level.

Learns the set of (source_role -> target_role) influence edges observed across
known-good executions. A role-level influence never seen in training -- e.g.
``marketing -> payment`` -- is treated as a HARD breach -> BLOCK. This is the
classic privilege-escalation / lateral-influence control: even if a brand new
agent shows up, if a *marketing* agent tries to drive a *payment* agent and
that pairing was never sanctioned, it is stopped.
"""

from __future__ import annotations

from collections import Counter

from .base import Invariant, InvariantResult
from .interaction_graph import InteractionGraph


class AuthorityInvariant(Invariant):
    name = "authority"

    def __init__(self, ignore_unknown: bool = True) -> None:
        self.ignore_unknown = ignore_unknown
        self.allowed_role_edges: set[tuple[str, str]] = set()
        self.role_edge_support: dict[tuple[str, str], float] = {}
        self.n_executions = 0

    def _eligible(self, edge: tuple[str, str]) -> bool:
        if not self.ignore_unknown:
            return True
        return "unknown" not in edge

    def learn(self, graphs: list[InteractionGraph]) -> None:
        self.n_executions = len(graphs)
        counts: Counter[tuple[str, str]] = Counter()
        for g in graphs:
            for edge in g.role_edges:
                if self._eligible(edge):
                    counts[edge] += 1
        self.allowed_role_edges = set(counts)
        if self.n_executions:
            self.role_edge_support = {
                e: c / self.n_executions for e, c in counts.items()
            }

    def check(self, graph: InteractionGraph) -> InvariantResult:
        violations: list[str] = []
        for s_role, t_role in sorted(graph.role_edges):
            edge = (s_role, t_role)
            if not self._eligible(edge):
                continue
            if edge not in self.allowed_role_edges:
                violations.append(
                    f"authority breach: {s_role} -> {t_role} is not a "
                    f"sanctioned influence relationship"
                )
        passed = not violations
        severity = 0.0 if passed else 1.0
        return InvariantResult(
            name=self.name,
            passed=passed,
            severity=severity,
            hard=bool(violations),  # unsanctioned influence is a hard breach
            violations=violations,
        )

    def describe(self) -> dict:
        return {
            "name": self.name,
            "allowed_role_edges": sorted(
                f"{s}->{t}" for s, t in self.allowed_role_edges
            ),
            "n_executions": self.n_executions,
        }
