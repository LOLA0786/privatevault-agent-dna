"""Pure-ASGI middleware that captures request and response bodies for the
one-line event log. Demo-grade: it buffers bodies (bounded) so the log can
show decision ids, permit ids and gate results. It changes nothing on the
wire."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

Observed = Callable[[str, str, dict[str, str], bytes, int, dict[str, str], bytes], None]
MAX_CAPTURE = 1_048_576


def _json(body: bytes) -> Any:
    try:
        return json.loads(body.decode("utf-8")) if body else None
    except (ValueError, UnicodeDecodeError):
        return None


class EventLog:
    """``observed(method, path, request_headers, request_body, status,
    response_headers, response_body)`` after each HTTP exchange."""

    def __init__(self, app: ASGIApp, observed: Observed) -> None:
        self.app = app
        self.observed = observed

    async def __call__(  # noqa: C901 - one branch per ASGI message type
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_chunks: list[bytes] = []
        response_chunks: list[bytes] = []
        status = {"code": 0}
        response_headers: dict[str, str] = {}

        async def receive_capture() -> Message:
            message = await receive()
            if message["type"] == "http.request":
                body = message.get("body", b"")
                if sum(map(len, request_chunks)) < MAX_CAPTURE:
                    request_chunks.append(body)
            return message

        async def send_capture(message: Message) -> None:
            if message["type"] == "http.response.start":
                status["code"] = int(message["status"])
                for key, value in message.get("headers", []):
                    response_headers[key.decode("latin-1").lower()] = value.decode(
                        "latin-1"
                    )
            elif message["type"] == "http.response.body":
                if sum(map(len, response_chunks)) < MAX_CAPTURE:
                    response_chunks.append(message.get("body", b""))
                if not message.get("more_body", False):
                    self._emit(
                        scope,
                        request_chunks,
                        status["code"],
                        response_headers,
                        response_chunks,
                    )
            await send(message)

        await self.app(scope, receive_capture, send_capture)

    def _emit(
        self,
        scope: Scope,
        request_chunks: list[bytes],
        status: int,
        response_headers: dict[str, str],
        response_chunks: list[bytes],
    ) -> None:
        request_headers = {
            k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in scope.get("headers", [])
        }
        try:
            self.observed(
                scope["method"],
                scope["path"],
                request_headers,
                b"".join(request_chunks),
                status,
                response_headers,
                b"".join(response_chunks),
            )
        except Exception as exc:  # logging must never break the service
            print(f"event log error: {type(exc).__name__}: {exc}", flush=True)


json_or_none = _json
