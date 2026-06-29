"""Shared base types for Cross-Agent Behavioral Invariants (CABI).

These are deliberately dependency-free (stdlib only) so the invariant engine
can run anywhere the runtime runs, including inside the hot enforcement path.
"""
from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # avoid import cycle at runtime
    from .interaction_graph import InteractionGraph


class Verdict(str, enum.Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


@dataclass
class InvariantResult:
    """Outcome of checking one invariant family against one execution graph.

    severity: 0.0 == clean, 1.0 == maximally anomalous (soft signal).
    hard:     True == a clear breach that should block on its own, regardless
              of severity aggregation.
    """
    name: str
    passed: bool
    severity: float = 0.0
    hard: bool = False
    violations: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        # clamp severity defensively; learned thresholds should never emit junk
        self.severity = max(0.0, min(1.0, float(self.severity)))


class Invariant(ABC):
    """An invariant family learns from a corpus of known-good executions and
    then scores a new execution graph against what it learned."""

    name: str = "invariant"

    @abstractmethod
    def learn(self, graphs: "list[InteractionGraph]") -> None:
        ...

    @abstractmethod
    def check(self, graph: "InteractionGraph") -> InvariantResult:
        ...

    # convenience so a freshly-constructed engine is introspectable
    def describe(self) -> dict:
        return {"name": self.name}
