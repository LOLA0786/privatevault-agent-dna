"""
Execution trace schema — the data contract for Agent DNA.

Everything upstream (your Temporal/multi-agent platform, the deterministic
firewall's decision log, MCP tool-call records) must be reduced to a stream of
`AgentAction`s before Agent DNA can learn a profile or score drift. Keeping this
contract small and explicit is what lets the same learning core sit behind very
different agent runtimes.

Design notes
------------
* `arguments` is treated as *untrusted* raw input. Agent DNA never matches on it
  verbatim; a FeatureExtractor (see manifold.py) reduces it to a handful of
  categorical / numeric features. This keeps the profile compact and avoids
  memorising payloads.
* `capability` is the unit of behaviour: a fully-qualified tool/action name,
  e.g. "salesforce.update_contact", "email.send", "wire.initiate". Namespacing
  matters — it is what lets the manifold notice "this agent has never touched the
  payments namespace before".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class AgentAction:
    """A single action an agent attempted (or took) at runtime."""

    agent_id: str
    capability: str
    timestamp: float
    arguments: Dict[str, Any] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    outcome: str = "ok"  # "ok" | "error" | "blocked"

    def __post_init__(self) -> None:
        if not self.agent_id:
            raise ValueError("AgentAction.agent_id is required")
        if not self.capability:
            raise ValueError("AgentAction.capability is required")


@dataclass
class ExecutionTrace:
    """An ordered sequence of actions for one agent run / session."""

    agent_id: str
    actions: List[AgentAction] = field(default_factory=list)

    def add(self, action: AgentAction) -> "ExecutionTrace":
        if action.agent_id != self.agent_id:
            raise ValueError(
                f"action.agent_id {action.agent_id!r} != trace.agent_id {self.agent_id!r}"
            )

        self.actions.append(action)
        return self

    @property
    def capabilities(self) -> List[str]:
        return [a.capability for a in self.actions]

    def __len__(self) -> int:
        return len(self.actions)
