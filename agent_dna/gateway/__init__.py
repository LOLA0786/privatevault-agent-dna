"""Inline MCP gateway — mediated egress with detectable bypass.

This is a **gateway**, not an adapter: the client connects to us
believing we are the MCP server. We hold upstream credentials and
evaluate every ``tools/call``, ``resources/read``, and
``resources/subscribe`` before any bytes are written upstream.
``sampling/createMessage`` is refused. Unknown methods fail closed.

See ``docs/WHAT-WE-DO-NOT-CLAIM.md`` for residual bypass paths.
"""

from __future__ import annotations

from agent_dna.gateway.errors import (
    ArgumentMutationRefused,
    ArgumentMutationRefusedError,
    CredentialLeakError,
    CrossOriginRedirectError,
    FramingProtocolError,
    GatewayStartupError,
    SameOriginRedirectError,
    UpstreamDeadError,
)
from agent_dna.gateway.framing import FramingMode
from agent_dna.gateway.runtime import GatewayConfig, McpGateway

__all__ = [
    "ArgumentMutationRefused",
    "ArgumentMutationRefusedError",
    "CredentialLeakError",
    "CrossOriginRedirectError",
    "FramingMode",
    "FramingProtocolError",
    "GatewayConfig",
    "GatewayStartupError",
    "McpGateway",
    "SameOriginRedirectError",
    "UpstreamDeadError",
]
