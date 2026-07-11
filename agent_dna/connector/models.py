"""
Canonical connector contract. Every adapter (MCP, OpenAI SDK,
LangGraph, ...) translates its framework's tool call into a
ToolCallRequest and its framework's response out of a
ToolCallVerdict. Adapters contain zero policy: one enforcement
path, N transports.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass(frozen=True, slots=True)
class ToolCallRequest:
    adapter: str                      # "mcp" | "openai" | ...
    tool: str                         # capability name, e.g. "payments.transfer"
    api_key: Optional[str]            # binds the caller to an agent identity
    arguments: Dict[str, Any] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    evidence: Optional[dict] = None   # UAAL/consensus/economics evidence pass-through


@dataclass(frozen=True, slots=True)
class ToolCallVerdict:
    decision: str                     # Decision enum value: allow|require_approval|block
    triggered_by: str
    reason: str
    agent_id: Optional[str]           # None only for identity refusals
    record_hash: Optional[str]        # None only when no chain record exists (identity/fault)
    signed: bool = False

    @property
    def allowed(self) -> bool:
        return self.decision == "allow"
