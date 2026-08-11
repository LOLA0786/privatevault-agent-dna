"""MCP JSON-RPC framing (Content-Length) and exact-byte serialization.

Production sessions use Content-Length framing only. Newline-delimited
JSON is test-only and cannot be selected by production GatewayConfig.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from agent_dna.authority_v01 import AuthorityFormatError, strict_json_loads
from agent_dna.execution_v01 import sha256_bytes_digest
from agent_dna.gateway.errors import FramingProtocolError

JSONRPC = "2.0"

# Header must terminate before this many bytes (8 KiB). Enough for
# Content-Length plus a few optional headers; small enough that a
# non-terminating peer cannot grow memory without bound.
MAX_HEADER_BYTES = 8 * 1024

# Default body/message cap (8 MiB). Configurable on GatewayConfig;
# oversized Content-Length is rejected before any body read.
DEFAULT_MAX_MESSAGE_BYTES = 8 * 1024 * 1024


class FramingMode(StrEnum):
    CONTENT_LENGTH = "content-length"
    NEWLINE = "newline"  # test-only


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


def parse_content_length(
    header: bytes,
    *,
    max_message_bytes: int,
) -> int:
    """Extract and validate Content-Length. Never returns a value to pass
    unchecked into ``read()``."""
    length: int | None = None
    for line in header.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            raw = line.split(b":", 1)[1].strip()
            if not raw or not raw.isdigit():
                raise FramingProtocolError(f"invalid Content-Length value: {raw!r}")
            length = int(raw)  # raw.isdigit() => non-negative
            break
    if length is None:
        raise FramingProtocolError("MCP frame missing Content-Length")
    if length > max_message_bytes:
        raise FramingProtocolError(
            f"Content-Length {length} exceeds max_message_bytes {max_message_bytes}"
        )
    return length


def parse_jsonrpc(
    data: bytes | str,
    *,
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
) -> dict[str, Any]:
    """Strict JSON-RPC 2.0 object parse. Size-checked before decode."""
    if isinstance(data, str):
        raw = data.encode("utf-8")
    else:
        raw = data
    if len(raw) > max_message_bytes:
        raise FramingProtocolError(
            f"JSON-RPC message length {len(raw)} exceeds max_message_bytes "
            f"{max_message_bytes}"
        )
    try:
        obj = strict_json_loads(raw)
    except AuthorityFormatError as exc:
        raise FramingProtocolError(str(exc)) from exc
    if not isinstance(obj, dict):
        raise FramingProtocolError("JSON-RPC message must be an object")
    if obj.get("jsonrpc") != JSONRPC:
        raise FramingProtocolError(
            f"jsonrpc field must be {JSONRPC!r}, got {obj.get('jsonrpc')!r}"
        )
    return obj


@dataclass
class FrameBuffer:
    """Stateful frame parser. Retains bytes after a complete frame."""

    mode: FramingMode
    max_header_bytes: int = MAX_HEADER_BYTES
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES
    _buf: bytearray = field(default_factory=bytearray)

    def push(self, data: bytes) -> None:
        if not data:
            return
        self._buf.extend(data)
        # Fail closed early if a non-terminating header is growing.
        if self.mode is FramingMode.CONTENT_LENGTH:
            if b"\r\n\r\n" not in self._buf and len(self._buf) > self.max_header_bytes:
                raise FramingProtocolError(
                    f"header exceeds MAX_HEADER_BYTES ({self.max_header_bytes})"
                )
        elif self.mode is FramingMode.NEWLINE:
            if b"\n" not in self._buf and len(self._buf) > self.max_message_bytes:
                raise FramingProtocolError(
                    f"newline frame exceeds max_message_bytes {self.max_message_bytes}"
                )

    def take_message(self) -> bytes | None:
        """Return the next complete message body, or None if incomplete.

        Content-Length mode returns the JSON body only (not the header).
        Newline mode returns one line without the trailing newline.
        Remainder stays in the buffer for subsequent calls.
        """
        if self.mode is FramingMode.CONTENT_LENGTH:
            return self._take_content_length()
        if self.mode is FramingMode.NEWLINE:
            return self._take_newline()
        raise FramingProtocolError(f"unknown framing mode {self.mode!r}")

    def take_all(self) -> list[bytes]:
        out: list[bytes] = []
        while True:
            msg = self.take_message()
            if msg is None:
                return out
            out.append(msg)

    @property
    def pending(self) -> bytes:
        return bytes(self._buf)

    def _take_content_length(self) -> bytes | None:
        sep = self._buf.find(b"\r\n\r\n")
        if sep < 0:
            if len(self._buf) > self.max_header_bytes:
                raise FramingProtocolError(
                    f"header exceeds MAX_HEADER_BYTES ({self.max_header_bytes})"
                )
            return None
        if sep > self.max_header_bytes:
            raise FramingProtocolError(
                f"header exceeds MAX_HEADER_BYTES ({self.max_header_bytes})"
            )
        header = bytes(self._buf[:sep])
        # Validated before any body consumption / oversized read.
        length = parse_content_length(header, max_message_bytes=self.max_message_bytes)
        body_start = sep + 4
        total = body_start + length
        if len(self._buf) < total:
            return None
        body = bytes(self._buf[body_start:total])
        del self._buf[:total]
        return body

    def _take_newline(self) -> bytes | None:
        nl = self._buf.find(b"\n")
        if nl < 0:
            if len(self._buf) > self.max_message_bytes:
                raise FramingProtocolError(
                    f"newline frame exceeds max_message_bytes {self.max_message_bytes}"
                )
            return None
        if nl > self.max_message_bytes:
            raise FramingProtocolError(
                f"newline frame exceeds max_message_bytes {self.max_message_bytes}"
            )
        line = bytes(self._buf[:nl])
        del self._buf[: nl + 1]
        if line.endswith(b"\r"):
            line = line[:-1]
        return line


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
