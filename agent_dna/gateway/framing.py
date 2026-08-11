"""MCP JSON-RPC framing (Content-Length) and exact-byte serialization."""

from __future__ import annotations

import json
from typing import Any

from agent_dna.execution_v01 import sha256_bytes_digest

JSONRPC = "2.0"


def encode_jsonrpc_message(message: dict[str, Any]) -> bytes:
    """Serialize one JSON-RPC object to exact UTF-8 bytes (no framing).

    Uses sorted keys and compact separators so the same logical message
    always yields the same bytes. This is the payload digested for
    exact-wire binding on the MCP gateway transport.
    """
    return json.dumps(
        message,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def frame_stdio(payload: bytes) -> bytes:
    """Wrap JSON bytes in MCP stdio Content-Length framing."""
    header = f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii")
    return header + payload


def build_tools_call_message(
    *,
    request_id: Any,
    tool_name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    return {
        "jsonrpc": JSONRPC,
        "id": request_id,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": dict(arguments),
        },
    }


def freeze_tools_call_bytes(
    *,
    request_id: Any,
    tool_name: str,
    arguments: dict[str, Any],
    framed: bool = True,
) -> tuple[bytes, str]:
    """Return (exact bytes to write upstream, sha256 digest of those bytes)."""
    message = build_tools_call_message(
        request_id=request_id,
        tool_name=tool_name,
        arguments=arguments,
    )
    payload = encode_jsonrpc_message(message)
    wire = frame_stdio(payload) if framed else payload
    return wire, sha256_bytes_digest(wire)


def parse_jsonrpc(data: bytes | str) -> dict[str, Any]:
    if isinstance(data, bytes):
        text = data.decode("utf-8")
    else:
        text = data
    obj = json.loads(text)
    if not isinstance(obj, dict):
        raise ValueError("JSON-RPC message must be an object")
    return obj


def mcp_error_response(
    request_id: Any,
    *,
    code: int,
    message: str,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": JSONRPC, "id": request_id, "error": err}


# MCP application error range (tool / policy refusals).
MCP_ENFORCEMENT_DENIED = -32001
MCP_ENFORCEMENT_APPROVAL = -32002
MCP_GATEWAY_FAULT = -32003
MCP_INDETERMINATE = -32004
