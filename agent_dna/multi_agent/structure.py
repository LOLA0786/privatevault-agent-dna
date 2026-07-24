"""Structural invariants on the approval graph.

Every other invariant family in CABI *learns*: topology allowlists the
edges seen in known-good executions, authority allowlists role-level
influence. They answer "was this seen before?"

This module answers a different and stronger question: "is this shape a
contradiction?" A directed cycle in an antisymmetric relation is wrong
by definition -- it is wrong even if every execution in the training
corpus contained it, and it is wrong on day one with no corpus at all.

Two consequences worth stating plainly:

  * These checks need NO training data. They are the only invariant
    family here whose correctness does not depend on the quality or
    realism of a learned baseline.
  * They are definitional, so they are HARD. A learned allowlist miss
    is an anomaly; a cycle in `approves` is a contradiction.

WHY ONLY THE APPROVAL RELATION
------------------------------
Cycle detection is applied to approval edges only, never to raw
interaction edges. Ordinary agent traffic is bidirectional -- A asks B,
B answers A -- so a 2-cycle in the interaction graph is normal and
flagging it would produce immediate false positives. The `approves`
relation is different: it is antisymmetric by definition. If A has
authority to approve B's action, B must not have authority to approve
A's. That is the machine-checkable form of segregation of duties.

MAPPING TO EXISTING CONTROLS
----------------------------
  self-approval      an agent approving its own action -- the exact
                     thing dual control exists to prevent
  mutual approval    A approves B and B approves A -- reciprocal
                     sign-off, the two-party version of self-approval
  approval cycle     A -> B -> C -> A -- collusion structure. No single
                     grant is wrong; the composition is. This is the
                     case that individual-agent authorization checks
                     cannot see by construction.

Standard library only, deterministic ordering throughout, so the same
graph always yields the same violations in the same order.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from .base import Invariant, InvariantResult
from .interaction_graph import InteractionGraph


@dataclass
class ApprovalGraph:
    """Directed graph of approval authority.

    An edge ``(a, b)`` means *a may approve b's actions*. Built either
    from a declared authority model (design-time control: check the
    configuration before anything runs) or from the approval-carrying
    edges of an observed execution (runtime control).
    """

    _adj: dict[str, set[str]] = field(default_factory=dict)

    # ---------------------------------------------------------- construction

    def grant(self, approver: str, subject: str) -> ApprovalGraph:
        self._adj.setdefault(approver, set()).add(subject)
        self._adj.setdefault(subject, set())
        return self

    @classmethod
    def from_pairs(cls, pairs: Iterable[tuple[str, str]]) -> ApprovalGraph:
        g = cls()
        for approver, subject in pairs:
            g.grant(approver, subject)
        return g

    @classmethod
    def from_execution(cls, graph: InteractionGraph) -> ApprovalGraph:
        """Approval edges only. An event with ``approval=True`` means the
        source exercised approval authority over the target's step."""
        return cls.from_pairs(
            (e.source, e.target) for e in graph.events if e.approval
        )

    # ------------------------------------------------------------- accessors

    @property
    def nodes(self) -> set[str]:
        return set(self._adj)

    @property
    def edges(self) -> set[tuple[str, str]]:
        return {(a, b) for a, targets in self._adj.items() for b in targets}

    def approvers_of(self, subject: str) -> set[str]:
        return {a for a, targets in self._adj.items() if subject in targets}

    def reachable_from(self, agent: str) -> set[str]:
        """Transitive closure: every agent whose actions ``agent`` can
        ultimately influence through a chain of approvals. Useful for the
        question individual grant checks cannot answer -- *what can this
        agent reach by composition?*"""
        seen: set[str] = set()
        stack = sorted(self._adj.get(agent, ()))
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            stack.extend(sorted(self._adj.get(node, ())))
        return seen

    # --------------------------------------------------------------- cycles

    def cycles(self) -> list[tuple[str, ...]]:
        """Every elementary cycle, each reported once, deterministically.

        Each cycle is discovered exactly once from its lexicographically
        smallest member: DFS starts at each node in sorted order and only
        traverses nodes strictly greater than the start, so rotations of
        the same cycle cannot be reported twice.

        Johnson's algorithm is asymptotically better; this is O(V*(V+E))
        with an explicit stack and is deliberately chosen because an
        auditor can read it. Authority graphs are tens of nodes, not
        millions.
        """
        found: list[tuple[str, ...]] = []
        for start in sorted(self._adj):
            stack: list[tuple[str, list[str]]] = [(start, [start])]
            while stack:
                node, path = stack.pop()
                for nxt in sorted(self._adj.get(node, ())):
                    if nxt == start:
                        found.append(tuple(path))
                    elif nxt > start and nxt not in path:
                        stack.append((nxt, path + [nxt]))
        # stable order: shortest first, then lexicographic
        return sorted(set(found), key=lambda c: (len(c), c))


@dataclass(frozen=True)
class StructuralViolation:
    kind: str          # self_approval | mutual_approval | approval_cycle
    agents: tuple[str, ...]
    detail: str


class StructuralAuthorityInvariant(Invariant):
    """Definitional structure checks on the approval graph.

    ``learn`` is a no-op and says so: these invariants hold without a
    corpus. That is the point of the family, not an omission.
    """

    name = "structural_authority"

    def __init__(self, check_execution_graph: bool = True) -> None:
        self.check_execution_graph = check_execution_graph
        self.declared: ApprovalGraph | None = None

    # ------------------------------------------------------- design-time use

    def declare(self, graph: ApprovalGraph) -> StructuralAuthorityInvariant:
        """Attach a declared authority model so the configuration itself
        can be validated before any agent runs."""
        self.declared = graph
        return self

    @staticmethod
    def analyse(graph: ApprovalGraph) -> list[StructuralViolation]:
        violations: list[StructuralViolation] = []
        for cycle in graph.cycles():
            if len(cycle) == 1:
                (a,) = cycle
                violations.append(StructuralViolation(
                    "self_approval", cycle,
                    f"{a} may approve its own actions -- dual control "
                    "exists precisely to prevent this"))
            elif len(cycle) == 2:
                a, b = cycle
                violations.append(StructuralViolation(
                    "mutual_approval", cycle,
                    f"{a} and {b} may approve each other -- reciprocal "
                    "sign-off is the two-party form of self-approval; "
                    "the approves relation must be antisymmetric"))
            else:
                path = " -> ".join(cycle) + f" -> {cycle[0]}"
                violations.append(StructuralViolation(
                    "approval_cycle", cycle,
                    f"circular approval authority: {path}. No individual "
                    "grant in this chain is wrong; the composition is a "
                    "segregation-of-duties breach that per-agent "
                    "authorization checks cannot detect"))
        return violations

    # ---------------------------------------------------- Invariant contract

    def learn(self, graphs: list[InteractionGraph]) -> None:
        """No-op by design. Structural contradictions are not learned."""
        return None

    def check(self, graph: InteractionGraph) -> InvariantResult:
        violations: list[StructuralViolation] = []

        if self.declared is not None:
            violations += self.analyse(self.declared)
        if self.check_execution_graph:
            observed = ApprovalGraph.from_execution(graph)
            for v in self.analyse(observed):
                if v not in violations:
                    violations.append(v)

        messages = [f"{v.kind}: {v.detail}" for v in violations]
        return InvariantResult(
            name=self.name,
            passed=not violations,
            severity=1.0 if violations else 0.0,
            hard=bool(violations),   # definitional breach, never advisory
            violations=messages,
        )

    def describe(self) -> dict:
        return {
            "name": self.name,
            "requires_training": False,
            "declared_edges": (
                sorted(f"{a}->{b}" for a, b in self.declared.edges)
                if self.declared else []
            ),
        }
