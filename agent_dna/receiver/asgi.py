"""HTTP deployment shapes for ``ReceiverGate``.

``ReceiverGateMiddleware`` wraps any ASGI application (FastAPI, Starlette, ...)
that *is* the system of record. ``ReceiverGateProxy`` is a standalone ASGI
reverse proxy placed in front of a system the operator cannot modify (for
example a core-banking server): run it with uvicorn and make it the only
network path to the upstream.

Both read the full request body (bounded), evaluate the gate off the event
loop, and on refusal answer without touching the downstream system. The
permit header is stripped before forwarding. On admission the response
carries ``X-PV-Receiver-Receipt`` (the signed receipt's digest) and
``X-PV-Receiver-Sequence``.

A refused request is never forwarded. An admitted request whose upstream
call then fails has still consumed its permit; it is not re-admitted
(consistent with ADR 0005: a burned permit is not retried).
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, MutableMapping
from http.client import HTTPConnection, HTTPSConnection
from typing import Any
from urllib.parse import urlsplit

import anyio

from agent_dna.authority_v01 import sha256_digest
from agent_dna.receiver.gate import ReceiverDecision, ReceiverGate
from agent_dna.receiver.permit_header import PERMIT_HEADER_LOWER

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

RECEIPT_HEADER = "X-PV-Receiver-Receipt"
SEQUENCE_HEADER = "X-PV-Receiver-Sequence"

_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
    }
)


def _target(scope: Scope) -> str:
    raw = scope.get("raw_path")
    path = raw.decode("latin-1") if isinstance(raw, bytes) else scope.get("path", "/")
    # raw_path excludes the query string in ASGI; reattach it verbatim.
    query = scope.get("query_string") or b""
    if query:
        path = f"{path}?{query.decode('latin-1')}"
    return str(path)


def _headers(scope: Scope) -> list[tuple[str, str]]:
    return [
        (k.decode("latin-1"), v.decode("latin-1")) for k, v in scope.get("headers", [])
    ]


async def _read_body(receive: Receive, limit: int) -> bytes | None:
    """Read the whole body; ``None`` if it exceeds ``limit``."""
    chunks: list[bytes] = []
    size = 0
    over = False
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        chunk = message.get("body", b"") or b""
        size += len(chunk)
        if size > limit:
            over = True
        elif chunk:
            chunks.append(chunk)
        if not message.get("more_body", False):
            break
    return None if over else b"".join(chunks)


async def _respond_json(send: Send, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
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


def _refusal_payload(decision: ReceiverDecision) -> dict[str, Any]:
    receipt = decision.receipt
    return {
        "admitted": False,
        "reason_code": decision.reason_code,
        "detail": decision.detail,
        "receipt_digest": None if receipt is None else sha256_digest(receipt),
        "receipt_sequence": None if receipt is None else receipt.get("sequence"),
    }


def _receipt_headers(decision: ReceiverDecision) -> list[tuple[bytes, bytes]]:
    if decision.receipt is None:
        return []
    return [
        (RECEIPT_HEADER.lower().encode(), sha256_digest(decision.receipt).encode()),
        (SEQUENCE_HEADER.lower().encode(), str(decision.receipt["sequence"]).encode()),
    ]


async def _evaluate(
    gate: ReceiverGate, scope: Scope, receive: Receive
) -> tuple[ReceiverDecision, bytes]:
    body = await _read_body(receive, gate.max_body_bytes)
    if body is None:
        # Bound exceeded; the body was not retained, so the refusal receipt
        # records the empty digest with reason RECEIVER_BODY_TOO_LARGE.
        oversize = await anyio.to_thread.run_sync(
            lambda: gate.refuse_unread_body(method=scope["method"], path=_target(scope))
        )
        return oversize, b""
    decision = await anyio.to_thread.run_sync(
        lambda: gate.check(
            method=scope["method"],
            path=_target(scope),
            headers=_headers(scope),
            body=body,
        )
    )
    return decision, body


class ReceiverGateMiddleware:
    """Gate every HTTP request to ``app``; refused requests never reach it."""

    def __init__(self, app: ASGIApp, gate: ReceiverGate) -> None:
        self.app = app
        self.gate = gate

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            if scope["type"] == "lifespan":
                await self.app(scope, receive, send)
                return
            # websockets and anything else cannot carry a bound body: refuse.
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return
        decision, body = await _evaluate(self.gate, scope, receive)
        if not decision.admitted:
            await _respond_json(send, decision.http_status, _refusal_payload(decision))
            return

        forwarded = dict(scope)
        forwarded["headers"] = [
            (k, v)
            for k, v in scope.get("headers", [])
            if k.decode("latin-1").lower() != PERMIT_HEADER_LOWER
        ]
        delivered = False

        async def replay() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        extra = _receipt_headers(decision)

        async def send_with_receipt(message: Message) -> None:
            if message["type"] == "http.response.start" and extra:
                message = dict(message)
                message["headers"] = [*message.get("headers", []), *extra]
            await send(message)

        await self.app(forwarded, replay, send_with_receipt)


class ReceiverGateProxy:
    """Standalone ASGI reverse proxy: gate, then forward to ``upstream``.

    ``upstream`` is a base URL such as ``https://core-banking:8443``. Plain
    ``http`` upstreams require ``allow_http_upstream=True`` (for a loopback
    sidecar inside one pod). Upstream TLS verification is on unless
    ``ca_file`` points at a private CA.
    """

    def __init__(
        self,
        gate: ReceiverGate,
        upstream: str,
        *,
        allow_http_upstream: bool = False,
        ca_file: str | None = None,
        timeout_s: float = 30.0,
        max_response_bytes: int = 8 * 1_048_576,
    ) -> None:
        parts = urlsplit(upstream)
        if parts.scheme not in {"https", "http"} or not parts.hostname:
            raise ValueError("upstream must be an http(s) base URL")
        if parts.scheme == "http" and not allow_http_upstream:
            raise ValueError("plain http upstream requires allow_http_upstream=True")
        self.gate = gate
        self.scheme = parts.scheme
        self.host = parts.hostname
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.ca_file = ca_file
        self.timeout_s = timeout_s
        self.max_response_bytes = max_response_bytes

    def _forward(
        self, method: str, target: str, headers: list[tuple[str, str]], body: bytes
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        if self.scheme == "https":
            import ssl

            ctx = ssl.create_default_context()
            if self.ca_file:
                ctx.load_verify_locations(cafile=self.ca_file)
            conn: HTTPConnection = HTTPSConnection(
                self.host, self.port, timeout=self.timeout_s, context=ctx
            )
        else:
            conn = HTTPConnection(self.host, self.port, timeout=self.timeout_s)
        try:
            out = {
                k: v
                for k, v in headers
                if k.lower() not in _HOP_BY_HOP and k.lower() != PERMIT_HEADER_LOWER
            }
            conn.request(method, target, body=body, headers=out)
            resp = conn.getresponse()
            data = resp.read(self.max_response_bytes + 1)
            if len(data) > self.max_response_bytes:
                raise RuntimeError("upstream response exceeds bound")
            return (
                int(resp.status),
                [(k, v) for k, v in resp.getheaders() if k.lower() not in _HOP_BY_HOP],
                data,
            )
        finally:
            conn.close()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return
        decision, body = await _evaluate(self.gate, scope, receive)
        if not decision.admitted:
            await _respond_json(send, decision.http_status, _refusal_payload(decision))
            return
        try:
            status, headers, data = await anyio.to_thread.run_sync(
                self._forward, scope["method"], _target(scope), _headers(scope), body
            )
        except Exception as exc:
            # The permit is consumed; the upstream outcome is unknown. Say so.
            await _respond_json(
                send,
                502,
                {
                    "admitted": True,
                    "upstream": "INDETERMINATE",
                    "detail": type(exc).__name__,
                    "receipt_digest": None
                    if decision.receipt is None
                    else sha256_digest(decision.receipt),
                },
            )
            return
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    *[
                        (k.lower().encode("latin-1"), v.encode("latin-1"))
                        for k, v in headers
                    ],
                    (b"content-length", str(len(data)).encode("ascii")),
                    *_receipt_headers(decision),
                ],
            }
        )
        await send({"type": "http.response.body", "body": data})
