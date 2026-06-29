"""The atomic unit of multi-agent behavior: a directed interaction event.

Every edge in an execution graph is one of these. An execution is the set of
events sharing an ``execution_id``. Roles (a.k.a. authority / department) are
carried on the edge because that is what the authority invariant reasons over:
*which kind of agent is allowed to influence which kind of agent*.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class InteractionEvent:
    execution_id: str
    source: str                       # acting agent id
    target: str                       # influenced agent / action sink id
    timestamp: float                  # monotonic within an execution

    source_role: str = "unknown"      # e.g. "finance"
    target_role: str = "unknown"      # e.g. "payment"

    trust: float = 1.0                # source trust at time of action [0,1]
    tool: Optional[str] = None        # tool/capability invoked, if any
    cost: float = 0.0                 # economic cost units of this step
    intent: Optional[str] = None      # declared intent of the step
    confidence: float = 1.0           # source confidence in the step [0,1]
    approval: bool = False            # was this step explicitly approved

    metadata: dict[str, Any] = field(default_factory=dict)

    def edge(self) -> tuple[str, str]:
        return (self.source, self.target)

    def role_edge(self) -> tuple[str, str]:
        return (self.source_role, self.target_role)
