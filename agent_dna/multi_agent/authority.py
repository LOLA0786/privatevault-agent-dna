"""Authority invariant: *who is allowed to influence whom*, at the role level.

Learns the set of (source_role -> target_role) influence edges observed across
known-good executions. A role-level influence never seen in training -- e.g.
``marketing -> payment`` -- is a HARD breach -> BLOCK.

UNRESOLVED ROLES ARE NOT SKIPPED
--------------------------------
An agent whose role never resolved carries the role ``unknown``. The previous
``ignore_unknown=True`` default skipped those edges at check time, so an
unidentified agent could drive a payment agent without breaching this
invariant -- a fail-open at the runtime call site. Removed.

Three rules, deliberately asymmetric:

  * learn: an ``unknown`` edge is NEVER admitted to the allowlist. An
    unresolved role must not become sanctioned by appearing in training.

  * check, unresolved SOURCE: an unidentified principal exercising influence
    is the privilege-escalation path. HARD breach -> BLOCK.

  * check, unresolved TARGET: a known principal influencing a newly-seen
    agent is novelty, not an attack. The invariant fails at PARTIAL severity
    and escalates for review rather than blocking -- consistent
    with uncertainty being ceiling-capped elsewhere in the runtime. Blocking
    here would halt execution every time a new agent joins a swarm, which is
    the kind of control teams switch off.

ABSENT ROLE MODEL vs UNRESOLVED ROLE
------------------------------------
These are different and must not be conflated. If training produced no
resolved role edges at all, roles are not in use in this deployment and this
invariant has no authority model to enforce. It abstains, and ``describe()``
reports ``role_model_trained: False`` so the gap is visible rather than
silent. Enforcing an authority model that was never learned is not
fail-closed; it blocks every execution regardless of behaviour, which is the
kind of control that gets disabled.

Once ANY resolved role edge has been learned, roles are in use, and an
unresolved role becomes meaningful: the deployment identifies principals and
this one was not identified.

Reason codes are distinct so an auditor can tell "we know this is wrong" from
"we cannot tell who this is".
"""

from __future__ import annotations

from collections import Counter

from .base import Invariant, InvariantResult
from .interaction_graph import InteractionGraph

UNKNOWN_ROLE = "unknown"


class AuthorityInvariant(Invariant):
    name = "authority"

    # Graded soft signal for an unresolved target. Must stay below the
    # engine's aggregate block threshold when contributed alone.
    UNRESOLVED_TARGET_SEVERITY = 0.5

    def __init__(self) -> None:
        self.allowed_role_edges: set[tuple[str, str]] = set()
        self.role_edge_support: dict[tuple[str, str], float] = {}
        self.n_executions = 0

    @staticmethod
    def _resolved(edge: tuple[str, str]) -> bool:
        return UNKNOWN_ROLE not in edge

    def learn(self, graphs: list[InteractionGraph]) -> None:
        self.n_executions = len(graphs)
        counts: Counter[tuple[str, str]] = Counter()
        for g in graphs:
            for edge in g.role_edges:
                # Unconditional: an unresolved role never becomes sanctioned.
                if self._resolved(edge):
                    counts[edge] += 1
        self.allowed_role_edges = set(counts)
        if self.n_executions:
            self.role_edge_support = {
                e: c / self.n_executions for e, c in counts.items()
            }

    @property
    def trained(self) -> bool:
        """True once at least one resolved role edge has been learned."""
        return bool(self.allowed_role_edges)

    def check(self, graph: InteractionGraph) -> InvariantResult:
        # No learned role model: roles are not in use here. Abstain rather
        # than enforce an authority model that does not exist.
        if not self.trained:
            return InvariantResult(
                name=self.name,
                passed=True,
                severity=0.0,
                hard=False,
                violations=[],
            )

        hard_violations: list[str] = []
        soft_violations: list[str] = []

        for s_role, t_role in sorted(graph.role_edges):
            if s_role == UNKNOWN_ROLE:
                hard_violations.append(
                    f"UNRESOLVED_ACTOR_INFLUENCE: {s_role} -> {t_role}: an "
                    f"unidentified principal cannot exercise influence"
                )
                continue
            if t_role == UNKNOWN_ROLE:
                soft_violations.append(
                    f"UNRESOLVED_TARGET_INFLUENCE: {s_role} -> {t_role}: "
                    f"target role unresolved; influence not verifiable"
                )
                continue
            if (s_role, t_role) not in self.allowed_role_edges:
                hard_violations.append(
                    f"UNSANCTIONED_INFLUENCE: {s_role} -> {t_role} is not a "
                    f"sanctioned influence relationship"
                )

        violations = hard_violations + soft_violations
        passed = not violations

        # Severity is graded, not binary. A maximal 1.0 for an unresolved
        # TARGET would clear the engine's aggregate soft-block threshold on
        # its own, blocking by the back door what hard=False just declined
        # to block. UNRESOLVED_TARGET is unverifiable influence by a KNOWN
        # actor: anomalous, not maximally so.
        if hard_violations:
            severity = 1.0
        elif soft_violations:
            severity = self.UNRESOLVED_TARGET_SEVERITY
        else:
            severity = 0.0

        return InvariantResult(
            name=self.name,
            passed=passed,
            severity=severity,
            # Only an unresolved ACTOR or an unsanctioned edge blocks.
            # An unresolved TARGET escalates.
            hard=bool(hard_violations),
            violations=violations,
        )

    def describe(self) -> dict:
        return {
            "name": self.name,
            "allowed_role_edges": sorted(
                f"{s}->{t}" for s, t in self.allowed_role_edges
            ),
            "n_executions": self.n_executions,
            "unresolved_source_policy": "hard_breach",
            "unresolved_target_policy": "escalate_review",
            "unresolved_target_severity": self.UNRESOLVED_TARGET_SEVERITY,
            "role_model_trained": self.trained,
        }
