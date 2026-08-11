"""Inline MCP gateway — mediated egress with detectable bypass.

This is a **gateway**, not an adapter: the client connects to us
believing we are the MCP server. We hold upstream credentials and
evaluate every ``tools/call`` before any bytes are written upstream.

See ``docs/WHAT-WE-DO-NOT-CLAIM.md`` for residual bypass paths.
"""

from __future__ import annotations

from agent_dna.gateway.errors import (
    ArgumentMutationRefused,
    ArgumentMutationRefusedError,
    CredentialLeakError,
    GatewayStartupError,
)
from agent_dna.gateway.runtime import GatewayConfig, McpGateway

__all__ = [
    "ArgumentMutationRefused",
    "ArgumentMutationRefusedError",
    "CredentialLeakError",
    "GatewayConfig",
    "GatewayStartupError",
    "McpGateway",
]
