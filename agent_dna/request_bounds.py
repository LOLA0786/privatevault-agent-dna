"""Bounded request bodies and JSON nesting for ASGI entry points (R1 #7).

Pure ASGI middleware that runs before routing, authentication, and body
parsing. It reads the whole body up to ``max_bytes`` (refusing with 413 past
that, whether or not ``Content-Length`` was declared), then, for JSON
bodies, counts container nesting on the raw bytes and refuses with 400 past
``max_json_depth``. Only then does the application see the request, with the
body replayed from memory.

Limits are supplied by a callable so the API can validate them once at
startup; when the callable yields nothing (for example an app used without
its lifespan) the built-in defaults apply, never "no limit".
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, MutableMapping
from dataclasses import dataclass
from typing import Any

from agent_dna.authority_v01 import MAX_JSON_NESTING_DEPTH

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE"
REQUEST_JSON_TOO_DEEP = "REQUEST_JSON_TOO_DEEP"
REQUEST_CONTENT_LENGTH_INVALID = "REQUEST_CONTENT_LENGTH_INVALID"

DEFAULT_MAX_REQUEST_BYTES = 1_048_576

_QUOTE = 0x22
_BACKSLASH = 0x5C
_OPENERS = (0x5B, 0x7B)  # [ {
_CLOSERS = (0x5D, 0x7D)  # ] }


@dataclass(frozen=True)
class RequestBounds:
    max_bytes: int
    max_json_depth: int


DEFAULT_REQUEST_BOUNDS = RequestBounds(
    max_bytes=DEFAULT_MAX_REQUEST_BYTES, max_json_depth=MAX_JSON_NESTING_DEPTH
)


def _skip_string(data: bytes, index: int) -> int:
    """Index just past the string whose opening quote is at ``index``."""
    i = index + 1
    n = len(data)
    while i < n:
        byte = data[i]
        if byte == _BACKSLASH:
            i += 2
            continue
        if byte == _QUOTE:
            return i + 1
        i += 1
    return n


def json_nesting_depth(data: bytes, limit: int | None = None) -> int:
    """Deepest container nesting in a JSON document, counted on raw bytes.

    Brackets inside strings are ignored (string state follows escapes). With
    ``limit`` set the scan returns ``limit + 1`` as soon as it is exceeded.
    This does not validate JSON; a malformed document yields a best-effort
    count and is left for the real parser to reject.
    """
    depth = 0
    deepest = 0
    i = 0
    n = len(data)
    while i < n:
        byte = data[i]
        if byte == _QUOTE:
            i = _skip_string(data, i)
            continue
        if byte in _OPENERS:
            depth += 1
            if depth > deepest:
                deepest = depth
                if limit is not None and deepest > limit:
                    return deepest
        elif byte in _CLOSERS and depth > 0:
            depth -= 1
        i += 1
    return deepest


async def _read_body(receive: Receive, limit: int) -> bytes | None:
    """Read the whole request body; ``None`` once it exceeds ``limit``."""
    chunks: list[bytes] = []
    size = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        chunk = message.get("body", b"") or b""
        size += len(chunk)
        if size > limit:
            return None
        if chunk:
            chunks.append(chunk)
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


async def _refuse(send: Send, status: int, reason_code: str, detail: str) -> None:
    body = json.dumps(
        {"detail": {"reason_code": reason_code, "detail": detail}}, sort_keys=True
    ).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _is_json(content_type: str) -> bool:
    media = content_type.split(";", 1)[0].strip().lower()
    # Starlette parses a body as JSON regardless of Content-Type, so an
    # absent type is treated as JSON here too.
    return media == "" or media.endswith("json")


def _declared_length_problem(
    headers: dict[str, str], bounds: RequestBounds
) -> tuple[int, str, str] | None:
    """(status, reason, detail) if Content-Length alone refuses the request."""
    declared = headers.get("content-length")
    if declared is None:
        return None
    try:
        length = int(declared)
    except ValueError:
        return 400, REQUEST_CONTENT_LENGTH_INVALID, "Content-Length is not an integer"
    if length < 0 or length > bounds.max_bytes:
        return (
            413,
            REQUEST_TOO_LARGE,
            f"request body exceeds {bounds.max_bytes} bytes",
        )
    return None


class RequestBoundsMiddleware:
    """Refuse oversize and over-nested requests before the app sees them."""

    def __init__(
        self,
        app: ASGIApp,
        bounds: Callable[[], RequestBounds | None] | None = None,
    ) -> None:
        self.app = app
        self.bounds = bounds or (lambda: DEFAULT_REQUEST_BOUNDS)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        bounds = self.bounds() or DEFAULT_REQUEST_BOUNDS
        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in scope.get("headers", [])
        }
        problem = _declared_length_problem(headers, bounds)
        if problem is not None:
            await _refuse(send, *problem)
            return
        body = await _read_body(receive, bounds.max_bytes)
        if body is None:
            await _refuse(
                send,
                413,
                REQUEST_TOO_LARGE,
                f"request body exceeds {bounds.max_bytes} bytes",
            )
            return
        if (
            body
            and _is_json(headers.get("content-type", ""))
            and json_nesting_depth(body, bounds.max_json_depth) > bounds.max_json_depth
        ):
            await _refuse(
                send,
                400,
                REQUEST_JSON_TOO_DEEP,
                f"JSON nesting exceeds {bounds.max_json_depth} levels",
            )
            return

        delivered = False

        async def replay() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)
