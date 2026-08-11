"""Upstream transports — the only place credentials are applied."""

from __future__ import annotations

import os
import select
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib import error as urlerror
from urllib import request as urlrequest

from agent_dna.gateway.credentials import UpstreamCredentials
from agent_dna.gateway.errors import FramingProtocolError, UpstreamTimeoutError
from agent_dna.gateway.framing import (
    DEFAULT_MAX_MESSAGE_BYTES,
    MAX_HEADER_BYTES,
    FrameBuffer,
    FramingMode,
    frame_stdio,
    parse_jsonrpc,
)


class UpstreamTransport(Protocol):
    identity: str

    def write(self, wire_bytes: bytes) -> None: ...

    def read_jsonrpc(self, *, timeout_s: float) -> dict[str, Any]: ...

    def close(self) -> None: ...


@dataclass
class RecordingUpstream:
    """In-process upstream for adversarial tests — records exact writes."""

    identity: str = "recording://test"
    writes: list[bytes] = field(default_factory=list)
    responses: list[dict[str, Any]] = field(default_factory=list)
    delay_s: float = 0.0
    closed: bool = False

    def write(self, wire_bytes: bytes) -> None:
        if self.closed:
            raise ConnectionError("upstream closed")
        self.writes.append(wire_bytes)

    def read_jsonrpc(self, *, timeout_s: float) -> dict[str, Any]:
        if self.delay_s > timeout_s:
            time.sleep(timeout_s)
            raise UpstreamTimeoutError("recording upstream timeout")
        if self.delay_s:
            time.sleep(self.delay_s)
        if not self.responses:
            raise UpstreamTimeoutError("recording upstream has no response")
        return self.responses.pop(0)

    def close(self) -> None:
        self.closed = True

    def queue_result(self, request_id: Any, result: Any) -> None:
        self.responses.append({"jsonrpc": "2.0", "id": request_id, "result": result})


@dataclass
class StdioUpstream:
    """Spawn/attach an upstream MCP server over stdio."""

    command: list[str]
    credentials: UpstreamCredentials
    identity: str = ""
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES
    framing_mode: FramingMode = FramingMode.CONTENT_LENGTH
    _proc: subprocess.Popen[bytes] | None = field(default=None, init=False, repr=False)
    _buffer: FrameBuffer | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.command:
            raise ValueError("StdioUpstream requires a non-empty command")
        if not self.identity:
            self.identity = "stdio:" + " ".join(self.command)
        if self.framing_mode is FramingMode.NEWLINE:
            raise ValueError(
                "StdioUpstream production path rejects newline framing; "
                "use Content-Length only"
            )
        self._buffer = FrameBuffer(
            mode=FramingMode.CONTENT_LENGTH,
            max_header_bytes=MAX_HEADER_BYTES,
            max_message_bytes=self.max_message_bytes,
        )

    def start(self) -> None:
        if self._proc is not None:
            return
        env = self.credentials.subprocess_env(os.environ)
        self._proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )

    def write(self, wire_bytes: bytes) -> None:
        self.start()
        if self._proc is None or self._proc.stdin is None:
            raise RuntimeError("stdio upstream process stdin unavailable")
        self._proc.stdin.write(wire_bytes)
        self._proc.stdin.flush()

    def read_jsonrpc(self, *, timeout_s: float) -> dict[str, Any]:
        self.start()
        if self._proc is None or self._proc.stdout is None:
            raise RuntimeError("stdio upstream process stdout unavailable")
        stdout = self._proc.stdout
        buffer = self._buffer
        if buffer is None:
            raise RuntimeError("stdio upstream frame buffer missing")
        deadline = time.monotonic() + timeout_s
        while True:
            ready = buffer.take_message()
            if ready is not None:
                return parse_jsonrpc(ready, max_message_bytes=self.max_message_bytes)
            remaining = max(0.0, deadline - time.monotonic())
            if remaining <= 0:
                raise UpstreamTimeoutError("stdio upstream timeout")
            readable, _, _ = select.select([stdout], [], [], remaining)
            if not readable:
                raise UpstreamTimeoutError("stdio upstream timeout")
            chunk = stdout.read(1)
            if not chunk:
                if buffer.pending:
                    raise UpstreamTimeoutError("incomplete MCP frame")
                raise UpstreamTimeoutError("stdio upstream EOF")
            try:
                buffer.push(chunk)
            except FramingProtocolError:
                raise

    def close(self) -> None:
        if self._proc is None:
            return
        self._proc.terminate()
        try:
            self._proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self._proc.kill()
        self._proc = None


@dataclass
class HttpSseUpstream:
    """Forward a single JSON-RPC POST to an upstream HTTP MCP endpoint."""

    url: str
    credentials: UpstreamCredentials
    identity: str = ""
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES

    def __post_init__(self) -> None:
        if not self.url:
            raise ValueError("HttpSseUpstream requires a url")
        if not self.identity:
            self.identity = "http:" + self.url
        self._last_response: dict[str, Any] | None = None
        self.writes: list[bytes] = []

    def write(self, wire_bytes: bytes) -> None:
        # Accept framed or raw JSON; HTTP body is the JSON payload.
        payload = wire_bytes
        if wire_bytes.startswith(b"Content-Length:"):
            payload = wire_bytes.split(b"\r\n\r\n", 1)[1]
        self.writes.append(wire_bytes)
        headers = {
            "Content-Type": "application/json",
            **self.credentials.http_headers(),
        }
        req = urlrequest.Request(self.url, data=payload, headers=headers, method="POST")
        try:
            with urlrequest.urlopen(req, timeout=30) as resp:
                body = resp.read(self.max_message_bytes + 1)
        except urlerror.URLError as exc:
            raise ConnectionError(f"upstream HTTP error: {exc}") from exc
        if len(body) > self.max_message_bytes:
            raise FramingProtocolError(
                f"upstream HTTP body exceeds max_message_bytes {self.max_message_bytes}"
            )
        self._last_response = parse_jsonrpc(
            body, max_message_bytes=self.max_message_bytes
        )

    def read_jsonrpc(self, *, timeout_s: float) -> dict[str, Any]:
        del timeout_s  # request was synchronous in write()
        if self._last_response is None:
            raise UpstreamTimeoutError("no upstream HTTP response")
        out = self._last_response
        self._last_response = None
        return out

    def close(self) -> None:
        return None


def encode_for_http_body(wire_bytes: bytes) -> bytes:
    """Strip stdio framing when posting over HTTP."""
    if wire_bytes.startswith(b"Content-Length:"):
        return wire_bytes.split(b"\r\n\r\n", 1)[1]
    return wire_bytes


def ensure_framed(payload: bytes) -> bytes:
    if payload.startswith(b"Content-Length:"):
        return payload
    return frame_stdio(payload)
