"""Upstream transports — the only place credentials are applied."""

from __future__ import annotations

import os
import select
import ssl
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urlparse

from agent_dna.gateway.credentials import UpstreamCredentials
from agent_dna.gateway.errors import (
    CrossOriginRedirectError,
    FramingProtocolError,
    SameOriginRedirectError,
    UpstreamDeadError,
    UpstreamTimeoutError,
)
from agent_dna.gateway.framing import (
    DEFAULT_MAX_MESSAGE_BYTES,
    MAX_HEADER_BYTES,
    MAX_JSON_DEPTH,
    FrameBuffer,
    FramingMode,
    frame_stdio,
    parse_jsonrpc,
)


class UpstreamTransport(Protocol):
    identity: str

    def bind_session(self, session_id: str) -> None: ...

    def write(self, wire_bytes: bytes) -> None: ...

    def read_jsonrpc(self, *, timeout_s: float) -> dict[str, Any]: ...

    def close(self) -> None: ...


def http_origin(url: str) -> tuple[str, str, int]:
    """Scheme, hostname, port — the sealed HTTP origin."""
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port
    if port is None:
        if scheme == "https":
            port = 443
        elif scheme == "http":
            port = 80
        else:
            port = 0
    return scheme, host, port


def origins_equal(left: str, right: str) -> bool:
    return http_origin(left) == http_origin(right)


class SealedDestinationRedirectHandler(urlrequest.HTTPRedirectHandler):
    """Never follow redirects. Cross-origin is refused; same-origin
    must be re-decided against the new location."""

    def redirect_request(
        self,
        req: urlrequest.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urlrequest.Request | None:
        current = req.get_full_url()
        if not origins_equal(current, newurl):
            raise CrossOriginRedirectError(
                f"refusing cross-origin redirect from {current} to {newurl}"
            )
        raise SameOriginRedirectError(newurl)


# Back-compat name used in phase-2 tests.
SameOriginRedirectHandler = SealedDestinationRedirectHandler


def read_bounded_http_body(
    resp: Any,
    *,
    max_bytes: int,
    chunk_size: int = 65536,
) -> bytes:
    """Read an HTTP/SSE body, failing closed if it exceeds ``max_bytes``."""
    if max_bytes <= 0:
        raise FramingProtocolError("max_bytes must be positive")
    buf = bytearray()
    while True:
        to_read = min(chunk_size, max_bytes + 1 - len(buf))
        chunk = resp.read(to_read)
        if not chunk:
            return bytes(buf)
        buf.extend(chunk)
        if len(buf) > max_bytes:
            raise FramingProtocolError(
                f"upstream HTTP/SSE body exceeds max_message_bytes {max_bytes}"
            )


@dataclass
class RecordingUpstream:
    """In-process upstream for adversarial tests — records exact writes."""

    identity: str = "recording://test"
    writes: list[bytes] = field(default_factory=list)
    responses: list[dict[str, Any]] = field(default_factory=list)
    delay_s: float = 0.0
    closed: bool = False
    dead: bool = False
    generation: int = 0
    session_id: str = ""
    attributions: list[str] = field(default_factory=list)
    redirect_once_to: str | None = None
    _redirect_raised: bool = field(default=False, init=False, repr=False)

    def bind_session(self, session_id: str) -> None:
        self.session_id = session_id

    def write(self, wire_bytes: bytes) -> None:
        if self.dead:
            raise UpstreamDeadError("upstream process is dead")
        if self.closed:
            raise UpstreamDeadError("upstream closed")
        if self.redirect_once_to and not self._redirect_raised:
            self._redirect_raised = True
            raise SameOriginRedirectError(self.redirect_once_to)
        self.writes.append(wire_bytes)
        self.attributions.append(self.session_id)

    def read_jsonrpc(self, *, timeout_s: float) -> dict[str, Any]:
        if self.dead:
            raise UpstreamDeadError("upstream process is dead")
        if self.closed:
            raise UpstreamDeadError("upstream closed")
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

    def queue_message(self, message: dict[str, Any]) -> None:
        self.responses.append(message)

    def die(self) -> None:
        self.dead = True
        self.closed = True

    def restart(self) -> None:
        """New process — a different principal. Session identity must not carry."""
        self.generation += 1
        self.identity = f"recording://test#gen{self.generation}"
        self.dead = False
        self.closed = False
        self.writes.clear()
        self.responses.clear()


@dataclass
class StdioUpstream:
    """Spawn/attach an upstream MCP server over stdio."""

    command: list[str]
    credentials: UpstreamCredentials
    identity: str = ""
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES
    max_json_depth: int = MAX_JSON_DEPTH
    framing_mode: FramingMode = FramingMode.CONTENT_LENGTH
    _proc: subprocess.Popen[bytes] | None = field(default=None, init=False, repr=False)
    _buffer: FrameBuffer | None = field(default=None, init=False, repr=False)
    _generation: int = field(default=0, init=False, repr=False)
    _session_id: str = field(default="", init=False, repr=False)

    def bind_session(self, session_id: str) -> None:
        self._session_id = session_id

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
        env = self.credentials.subprocess_env(os.environ, session_id=self._session_id)
        self._proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        if self._generation > 0:
            self.identity = (
                "stdio:" + " ".join(self.command) + f"#gen{self._generation}"
            )

    def write(self, wire_bytes: bytes) -> None:
        self.start()
        if self._proc is None or self._proc.stdin is None:
            raise UpstreamDeadError("stdio upstream process stdin unavailable")
        try:
            self._proc.stdin.write(wire_bytes)
            self._proc.stdin.flush()
        except BrokenPipeError as exc:
            raise UpstreamDeadError("stdio upstream stdin closed") from exc

    def read_jsonrpc(self, *, timeout_s: float) -> dict[str, Any]:
        self.start()
        if self._proc is None or self._proc.stdout is None:
            raise UpstreamDeadError("stdio upstream process stdout unavailable")
        stdout = self._proc.stdout
        buffer = self._buffer
        if buffer is None:
            raise RuntimeError("stdio upstream frame buffer missing")
        deadline = time.monotonic() + timeout_s
        while True:
            ready = buffer.take_message()
            if ready is not None:
                return parse_jsonrpc(
                    ready,
                    max_message_bytes=self.max_message_bytes,
                    max_json_depth=self.max_json_depth,
                )
            remaining = max(0.0, deadline - time.monotonic())
            if remaining <= 0:
                raise UpstreamTimeoutError("stdio upstream timeout")
            readable, _, _ = select.select([stdout], [], [], remaining)
            if not readable:
                raise UpstreamTimeoutError("stdio upstream timeout")
            chunk = stdout.read(1)
            if not chunk:
                self._raise_stdio_eof(buffer)
            try:
                buffer.push(chunk)
            except FramingProtocolError:
                raise

    def _raise_stdio_eof(self, buffer: FrameBuffer) -> None:
        if self._proc is not None and self._proc.poll() is not None:
            raise UpstreamDeadError("stdio upstream process exited")
        if buffer.pending:
            raise UpstreamTimeoutError("incomplete MCP frame")
        raise UpstreamDeadError("stdio upstream EOF")

    def close(self) -> None:
        if self._proc is None:
            return
        self._proc.terminate()
        try:
            self._proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self._proc.kill()
        self._proc = None
        self._generation += 1
        self.identity = (
            "stdio:" + " ".join(self.command) + f"#closed-{self._generation}"
        )


@dataclass
class HttpSseUpstream:
    """Forward a single JSON-RPC POST to an upstream HTTP MCP endpoint."""

    url: str
    credentials: UpstreamCredentials
    identity: str = ""
    max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES
    max_json_depth: int = MAX_JSON_DEPTH
    tls_verify: bool = True
    timeout_s: float = 30.0

    def __post_init__(self) -> None:
        if not self.url:
            raise ValueError("HttpSseUpstream requires a url")
        if not self.identity:
            self.identity = "http:" + self.url
        self._last_response: dict[str, Any] | None = None
        self.writes: list[bytes] = []
        self._ssl_context = self._build_ssl_context()
        self._opener = urlrequest.build_opener(
            SealedDestinationRedirectHandler(),
            urlrequest.HTTPSHandler(context=self._ssl_context),
        )
        self._session_id: str = ""

    def bind_session(self, session_id: str) -> None:
        self._session_id = session_id

    def _build_ssl_context(self) -> ssl.SSLContext:
        if self.tls_verify:
            return ssl.create_default_context()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def write(self, wire_bytes: bytes) -> None:
        # Accept framed or raw JSON; HTTP body is the JSON payload.
        payload = wire_bytes
        if wire_bytes.startswith(b"Content-Length:"):
            payload = wire_bytes.split(b"\r\n\r\n", 1)[1]
        self.writes.append(wire_bytes)
        headers = {
            "Content-Type": "application/json",
            **self.credentials.http_headers(session_id=self._session_id),
        }
        req = urlrequest.Request(self.url, data=payload, headers=headers, method="POST")
        try:
            with self._opener.open(req, timeout=self.timeout_s) as resp:
                body = read_bounded_http_body(resp, max_bytes=self.max_message_bytes)
        except CrossOriginRedirectError:
            raise
        except SameOriginRedirectError:
            raise
        except urlerror.URLError as exc:
            reason = getattr(exc, "reason", None)
            if isinstance(reason, CrossOriginRedirectError):
                raise reason from exc
            if isinstance(reason, SameOriginRedirectError):
                raise reason from exc
            raise ConnectionError(f"upstream HTTP error: {exc}") from exc
        self._last_response = parse_jsonrpc(
            body,
            max_message_bytes=self.max_message_bytes,
            max_json_depth=self.max_json_depth,
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
