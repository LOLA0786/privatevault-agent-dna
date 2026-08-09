"""Definitional dual-control (maker ≠ checker) invariant.

No training corpus. Same agent initiating and approving a payment-shaped
capability in one execution is a hard BLOCK — the segregation-of-duties
rule that individual-agent checks cannot see.
"""

from __future__ import annotations

from .base import Invariant, InvariantResult
from .interaction_graph import InteractionGraph


def is_initiate_intent(intent: str) -> bool:
    text = (intent or "").lower()
    return (
        ".initiate" in text
        or "initiate_" in text
        or text.endswith(".create")
        or ".submit" in text
    )


def is_approve_intent(intent: str, *, approval_flag: bool = False) -> bool:
    if approval_flag:
        return True
    text = (intent or "").lower()
    return ".approve" in text or text.startswith("approve") or ".signoff" in text


class DualControlInvariant(Invariant):
    name = "dual_control"

    def learn(self, graphs: list[InteractionGraph]) -> None:
        return None

    def check(self, graph: InteractionGraph) -> InvariantResult:
        initiators: set[str] = set()
        approvers: set[str] = set()
        for event in graph.events:
            if is_initiate_intent(event.intent):
                initiators.add(event.source)
            if is_approve_intent(event.intent, approval_flag=bool(event.approval)):
                approvers.add(event.source)
        both = sorted(initiators & approvers)
        if both:
            return InvariantResult(
                name=self.name,
                passed=False,
                severity=1.0,
                hard=True,
                violations=[
                    f"maker==checker: {both} initiated and approved in "
                    f"execution {graph.execution_id!r}"
                ],
            )
        return InvariantResult(name=self.name, passed=True)

    def describe(self) -> dict:
        return {
            "name": self.name,
            "requires_training": False,
            "rule": "same agent must not initiate and approve in one execution",
        }
