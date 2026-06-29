"""Consensus invariant: *who must agree before a consequential action fires*.

This is the family that catches the failure no single-agent monitor can see:
each approver may be behaving perfectly on its own, yet the *collective*
sign-off required before execution was never reached.

  Historically:  Risk=yes, Finance=yes, Legal=yes  ->  payment executes.
  Now:           Risk=NO,  Finance=yes, Legal=(silent) ->  payment executes.
                 -> consensus invariant violated -> HARD -> BLOCK.

What it learns
--------------
For every role that acts as a *gate* (a target role that consequential steps
flow into, e.g. ``payment``), it learns the set of approver roles that, in
known-good executions, reliably signed off (emitted ``approval=True`` with
sufficient confidence) *before* the gate fired. Only gates with a stable,
high-support approver set acquire a constraint; everything else stays
unconstrained, so the invariant is silent unless real sign-off structure
exists in the corpus.

What it flags at runtime
------------------------
For each learned gate present in an execution:
  * a required approver that never signed off before the gate   -> "silent"
  * a required approver that explicitly dissented (approval=False) -> "dissent"
  * a required approver that signed off only *after* the gate fired -> caught
    as silent (we only count sign-offs strictly before the gate)
Any of these is a HARD breach.
"""
from __future__ import annotations

from collections import defaultdict

from .base import Invariant, InvariantResult
from .interaction_graph import InteractionGraph


class ConsensusInvariant(Invariant):
    name = "consensus"

    def __init__(self, support_threshold: float = 0.95,
                min_confidence: float = 0.0,
                min_gate_support: int = 5) -> None:
        self.support_threshold = support_threshold
        self.min_confidence = min_confidence
        self.min_gate_support = min_gate_support
        # gate_role -> set of approver roles that must sign off before it
        self.required_approvers: dict[str, set[str]] = {}
        self.n_executions = 0

    # ---- helpers ----------------------------------------------------------
    def _approvals(self, graph: InteractionGraph) -> dict[str, float]:
        """role -> earliest timestamp at which it signed off (approval=True
        with confidence >= min_confidence)."""
        out: dict[str, float] = {}
        for e in graph.events:
            if not e.approval:
                continue
            if e.confidence < self.min_confidence:
                continue
            r = e.source_role
            if r == "unknown":
                continue
            if r not in out or e.timestamp < out[r]:
                out[r] = e.timestamp
        return out

    def _dissents(self, graph: InteractionGraph) -> dict[str, float]:
        """role -> earliest timestamp at which it explicitly dissented
        (approval=False)."""
        out: dict[str, float] = {}
        for e in graph.events:
            if e.approval:
                continue
            # only events that are *about* sign-off carry intent to dissent;
            # we treat an explicit approval=False with a sign-off intent marker
            if not e.metadata.get("is_signoff", False):
                continue
            r = e.source_role
            if r == "unknown":
                continue
            if r not in out or e.timestamp < out[r]:
                out[r] = e.timestamp
        return out

    # ---- learning ---------------------------------------------------------
    def learn(self, graphs: list[InteractionGraph]) -> None:
        self.n_executions = len(graphs)
        gate_count: dict[str, int] = defaultdict(int)
        approver_count: dict[tuple[str, str], int] = defaultdict(int)

        for g in graphs:
            gate_first = g.role_first_seen()
            approvals = self._approvals(g)
            for gate_role, gate_t in gate_first.items():
                if gate_role == "unknown":
                    continue
                approving = {
                    r for r, ts in approvals.items()
                    if ts < gate_t and r != gate_role
                }
                if not approving:
                    continue
                gate_count[gate_role] += 1
                for r in approving:
                    approver_count[(gate_role, r)] += 1

        self.required_approvers.clear()
        for gate_role, n in gate_count.items():
            if n < self.min_gate_support:
                continue
            req = {
                r for (g_role, r), c in approver_count.items()
                if g_role == gate_role and c / n >= self.support_threshold
            }
            if req:
                self.required_approvers[gate_role] = req

    # ---- checking ---------------------------------------------------------
    def check(self, graph: InteractionGraph) -> InvariantResult:
        gate_first = graph.role_first_seen()
        approvals = self._approvals(graph)
        dissents = self._dissents(graph)

        violations: list[str] = []
        for gate_role, required in sorted(self.required_approvers.items()):
            if gate_role not in gate_first:
                continue  # gate absent -> vacuously satisfied
            gate_t = gate_first[gate_role]
            for approver in sorted(required):
                approved_ts = approvals.get(approver)
                if approved_ts is not None and approved_ts < gate_t:
                    continue  # signed off in time
                dissent_ts = dissents.get(approver)
                if dissent_ts is not None and dissent_ts < gate_t:
                    violations.append(
                        f"consensus breach: {approver} dissented "
                        f"(approval=False) before {gate_role} executed"
                    )
                else:
                    violations.append(
                        f"consensus breach: {approver} did not sign off before "
                        f"{gate_role} executed (required approver silent)"
                    )

        passed = not violations
        return InvariantResult(
            name=self.name,
            passed=passed,
            severity=0.0 if passed else 1.0,
            hard=bool(violations),
            violations=violations,
        )

    def describe(self) -> dict:
        return {
            "name": self.name,
            "min_confidence": self.min_confidence,
            "required_approvers": {
                gate: sorted(approvers)
                for gate, approvers in sorted(self.required_approvers.items())
            },
            "n_executions": self.n_executions,
        }
