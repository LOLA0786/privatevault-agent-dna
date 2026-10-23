"""Stdio MCP proxy loop — client stdin/stdout speak MCP; we mediate."""

from __future__ import annotations

import select
import sys
from typing import BinaryIO, TextIO

from agent_dna.gateway.errors import FramingProtocolError
from agent_dna.gateway.framing import (
    DEFAULT_MAX_MESSAGE_BYTES,
    MAX_HEADER_BYTES,
    FrameBuffer,
    FramingMode,
    encode_jsonrpc_message,
    mcp_error_response,
    parse_jsonrpc,
)
from agent_dna.gateway.runtime import McpGateway

INVALID_REQUEST = -32600  # JSON-RPC 2.0


def _read_stdio_message(
    stream: BinaryIO,
    buffer: FrameBuffer,
    *,
    timeout_s: float | None = None,
) -> bytes | None:
    """Read one framed message into ``buffer`` (newline or Content-Length).

    Returns the message body, or None on clean EOF with an empty buffer.
    Incomplete frames at EOF / timeout raise FramingProtocolError or return
    None only when no bytes were pending (client disconnect).
    """
    while True:
        ready_msg = buffer.take_message()
        if ready_msg is not None:
            return ready_msg
        if timeout_s is not None:
            ready, _, _ = select.select([stream], [], [], timeout_s)
            if not ready:
                if buffer.pending:
                    raise FramingProtocolError(
                        "incomplete MCP frame (read timeout with pending bytes)"
                    )
                return None
        # Without a timeout, take whatever is buffered (read1): one byte at a
        # time made an 8 MiB frame take minutes (red team 2026-10-23, W10).
        # With one, read a byte so select() and the buffer stay in step.
        read1 = getattr(stream, "read1", None) if timeout_s is None else None
        chunk = read1(65536) if read1 is not None else stream.read(1)
        if not chunk:
            if buffer.pending:
                raise FramingProtocolError(
                    "incomplete MCP frame (EOF with pending bytes)"
                )
            return None
        buffer.push(chunk)


def serve_stdio(
    gateway: McpGateway,
    *,
    client_in: BinaryIO | None = None,
    client_out: BinaryIO | None = None,
) -> None:
    """Run the stdio proxy until the client disconnects."""
    if gateway.config.transport != "stdio":
        raise ValueError("serve_stdio requires transport=stdio")
    cin = client_in if client_in is not None else sys.stdin.buffer
    cout = client_out if client_out is not None else sys.stdout.buffer
    mediator = gateway.open_session()
    buffer = FrameBuffer(
        mode=gateway.config.framing_mode,
        max_header_bytes=MAX_HEADER_BYTES,
        max_message_bytes=gateway.config.max_message_bytes,
    )
    while True:
        try:
            raw = _read_stdio_message(cin, buffer)
        except FramingProtocolError:
            mediator.mark_client_disconnected()
            raise
        if raw is None:
            mediator.mark_client_disconnected()
            break
        if not raw.strip():
            continue  # blank line between newline-framed messages
        try:
            parse_jsonrpc(
                raw,
                max_message_bytes=gateway.config.max_message_bytes,
                max_json_depth=gateway.config.max_json_depth,
            )
        except FramingProtocolError as exc:
            # A malformed message (batch, float id, too deep) is answered and
            # dropped; the session goes on (red team 2026-10-23, F10).
            refusal = mcp_error_response(
                None, code=INVALID_REQUEST, message=f"invalid request: {exc}"
            )
            cout.write(mediator._frame(encode_jsonrpc_message(refusal)))
            cout.flush()
            continue
        response = mediator.handle_raw(raw)
        if response:
            cout.write(response)
            cout.flush()


def serve_stdio_text(
    gateway: McpGateway,
    *,
    lines_in: TextIO,
    lines_out: TextIO,
) -> None:
    """Test-only newline JSON loop. Requires ``_test_allow_newline_framing``."""
    if not gateway.config._test_allow_newline_framing:
        raise ValueError(
            "serve_stdio_text requires GatewayConfig._test_allow_newline_framing"
        )
    if gateway.config.framing_mode is not FramingMode.NEWLINE:
        raise ValueError("serve_stdio_text requires framing_mode=newline")
    mediator = gateway.open_session()
    mediator.framed = False
    buffer = FrameBuffer(
        mode=FramingMode.NEWLINE,
        max_header_bytes=MAX_HEADER_BYTES,
        max_message_bytes=gateway.config.max_message_bytes
        if gateway.config.max_message_bytes
        else DEFAULT_MAX_MESSAGE_BYTES,
    )
    for line in lines_in:
        buffer.push(line.encode("utf-8"))
        for raw in buffer.take_all():
            if not raw.strip():
                continue
            response = mediator.handle_raw(raw)
            if response:
                lines_out.write(response.decode("utf-8") + "\n")
                lines_out.flush()
    mediator.mark_client_disconnected()
