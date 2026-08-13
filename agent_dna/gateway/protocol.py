"""MCP method classification and JSON-RPC id correlation.

Classification is by exact membership in frozen sets — never by
substring matching. Unknown methods fail closed.
"""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Any

from agent_dna.gateway.errors import FramingProtocolError

# Exact method names. Membership is the only classifier.
GATED_METHODS = frozenset(
    {
        "tools/call",
        "resources/read",
        "resources/subscribe",
        "prompts/get",
    }
)
# Recorded and forwarded without a mintable decision. These are
# session/capability negotiation or non-effecting reads of catalogs.
PASSTHROUGH_METHODS = frozenset(
    {
        "initialize",
        "notifications/initialized",
        "notifications/cancelled",
        "ping",
        "tools/list",
        "prompts/list",
        "resources/list",
        "resources/templates/list",
        "logging/setLevel",
    }
)
# Server-initiated sampling would let an untrusted upstream drive the
# client's model. Always refused, never forwarded.
REFUSED_METHODS = frozenset(
    {
        "sampling/createMessage",
    }
)


class MethodClass(StrEnum):
    GATED = "gated"
    PASSTHROUGH = "passthrough"
    REFUSED = "refused"
    UNKNOWN = "unknown"


def classify_method(method: Any) -> MethodClass:
    if not isinstance(method, str) or not method:
        return MethodClass.UNKNOWN
    if method in GATED_METHODS:
        return MethodClass.GATED
    if method in PASSTHROUGH_METHODS:
        return MethodClass.PASSTHROUGH
    if method in REFUSED_METHODS:
        return MethodClass.REFUSED
    return MethodClass.UNKNOWN


def jsonrpc_id_key(request_id: Any) -> str:
    """Canonical map key for a JSON-RPC id (string or number, not bool)."""
    if request_id is None:
        raise FramingProtocolError("JSON-RPC id is required for correlation")
    if isinstance(request_id, bool) or not isinstance(request_id, (int, str)):
        raise FramingProtocolError("JSON-RPC id must be a string or integer")
    return json.dumps(request_id, separators=(",", ":"))


def is_jsonrpc_request(message: dict[str, Any]) -> bool:
    return "method" in message


def is_jsonrpc_response(message: dict[str, Any]) -> bool:
    return "method" not in message and ("result" in message or "error" in message)


def json_depth(value: Any, *, limit: int, depth: int = 1) -> None:
    if depth > limit:
        raise FramingProtocolError(f"JSON nesting exceeds max depth {limit}")
    if isinstance(value, dict):
        for child in value.values():
            json_depth(child, limit=limit, depth=depth + 1)
    elif isinstance(value, list):
        for child in value:
            json_depth(child, limit=limit, depth=depth + 1)


def tool_names_from_list_result(result: Any) -> frozenset[str]:
    if not isinstance(result, dict):
        return frozenset()
    tools = result.get("tools")
    if not isinstance(tools, list):
        return frozenset()
    names: list[str] = []
    for item in tools:
        if isinstance(item, dict):
            name = item.get("name")
            if isinstance(name, str) and name:
                names.append(name)
    return frozenset(names)
