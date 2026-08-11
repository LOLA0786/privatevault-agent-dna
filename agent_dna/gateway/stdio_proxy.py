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
)
from agent_dna.gateway.runtime import McpGateway


def _read_stdio_message(
    stream: BinaryIO,
    buffer: FrameBuffer,
    *,
    timeout_s: float | None = None,
) -> bytes | None:
    """Read one framed message into ``buffer``. Production uses Content-Length.

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
        chunk = stream.read(1)
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
    if gateway.config.framing_mode is not FramingMode.CONTENT_LENGTH:
        raise ValueError("serve_stdio requires content-length framing")
    cin = client_in if client_in is not None else sys.stdin.buffer
    cout = client_out if client_out is not None else sys.stdout.buffer
    mediator = gateway.open_session()
    buffer = FrameBuffer(
        mode=FramingMode.CONTENT_LENGTH,
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
        response = mediator.handle_raw(raw)
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
            lines_out.write(response.decode("utf-8") + "\n")
            lines_out.flush()
    mediator.mark_client_disconnected()
