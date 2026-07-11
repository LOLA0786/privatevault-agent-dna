"""
MCP adapter — wraps a FastMCP server so EVERY tools/call routes
through the ConnectorMiddleware before the tool executes.

Identity is connection-level: the harness supplies the agent's key
via the PV_AGENT_KEY env var (the standard MCP credential pattern —
harness config sets "env": {"PV_AGENT_KEY": "pv_..."}) or an
explicit api_key argument.

Interception point is ToolManager.call_tool — the single dispatch
path for all tools, including tools registered after guarding.
NOTE: touches FastMCP._tool_manager (private surface); pinned by
requirements to mcp>=1.0 and covered by an in-memory integration
test that fails loudly if the SDK surface changes.

Verdict mapping:
  ALLOW            -> original tool executes, result returned
  BLOCK            -> EnforcementBlocked -> MCP tool error, signed
                      record_hash and trigger in-band
  REQUIRE_APPROVAL -> same error path, marked pending approval;
                      the action does NOT execute
"""

from __future__ import annotations

import os
from typing import Any, Optional

from ..models import ToolCallRequest

PV_KEY_ENV = "PV_AGENT_KEY"


class EnforcementBlocked(Exception):
    def __init__(self, verdict):
        self.verdict = verdict
        prefix = (
            "PrivateVault REQUIRE_APPROVAL (pending, not executed)"
            if verdict.decision == "require_approval"
            else "PrivateVault BLOCK"
        )
        super().__init__(
            f"{prefix} [{verdict.triggered_by}] {verdict.reason} "
            f"record_hash={verdict.record_hash}"
        )


def guard_fastmcp(server, middleware, api_key: Optional[str] = None):
    """Returns the same server instance, with enforcement installed."""
    key = api_key if api_key is not None else os.environ.get(PV_KEY_ENV)
    tm = server._tool_manager
    original_call_tool = tm.call_tool

    async def enforced_call_tool(
        name: str, arguments: dict[str, Any], *args, **kwargs
    ):
        verdict = middleware.handle(
            ToolCallRequest(
                adapter="mcp",
                tool=name,
                api_key=key,
                arguments=dict(arguments or {}),
            )
        )
        if verdict.decision == "allow":
            return await original_call_tool(name, arguments, *args, **kwargs)
        raise EnforcementBlocked(verdict)

    tm.call_tool = enforced_call_tool
    return server
