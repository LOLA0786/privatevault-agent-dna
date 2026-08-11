"""Stdio MCP proxy loop — client stdin/stdout speak MCP; we mediate."""

from __future__ import annotations

import select
import sys
from typing import BinaryIO, TextIO

from agent_dna.gateway.runtime import McpGateway


def _content_length(header: bytes) -> int | None:
    for line in header.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            return int(line.split(b":", 1)[1].strip())
    return None


def _read_exact(stream: BinaryIO, length: int) -> bytes | None:
    body = stream.read(length)
    if len(body) < length:
        return None
    return body


def _read_stdio_message(
    stream: BinaryIO, *, timeout_s: float | None = None
) -> bytes | None:
    """Read one Content-Length framed message, or one newline-delimited JSON."""
    if timeout_s is not None:
        ready, _, _ = select.select([stream], [], [], timeout_s)
        if not ready:
            return None
    header = b""
    while True:
        ch = stream.read(1)
        if not ch:
            return None if not header else header
        header += ch
        if header.endswith(b"\r\n\r\n"):
            length = _content_length(header)
            if length is None:
                raise ValueError("MCP frame missing Content-Length")
            return _read_exact(stream, length)
        if header.endswith(b"\n") and b"Content-Length" not in header:
            return header.strip()


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
    while True:
        raw = _read_stdio_message(cin)
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
    """Test-friendly newline-delimited JSON loop (no Content-Length)."""
    mediator = gateway.open_session()
    # Temporarily unframed for line mode
    mediator.framed = False
    for line in lines_in:
        line = line.strip()
        if not line:
            continue
        response = mediator.handle_raw(line.encode("utf-8"))
        lines_out.write(response.decode("utf-8") + "\n")
        lines_out.flush()
    mediator.mark_client_disconnected()
