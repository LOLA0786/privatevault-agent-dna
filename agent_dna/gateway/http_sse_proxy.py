"""HTTP/SSE MCP proxy — same mediation semantics as stdio."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from agent_dna.gateway.framing import encode_jsonrpc_message, parse_jsonrpc
from agent_dna.gateway.mediator import GatewayMediator
from agent_dna.gateway.runtime import McpGateway


def handle_http_jsonrpc(
    gateway: McpGateway,
    body: bytes,
    *,
    mediator: GatewayMediator | None = None,
) -> tuple[int, bytes, dict[str, str]]:
    """Mediate one HTTP JSON-RPC POST body.

    Returns ``(status_code, response_body, headers)``.
    """
    if gateway.config.transport != "http+sse":
        raise ValueError("handle_http_jsonrpc requires transport=http+sse")
    active = mediator if mediator is not None else gateway.open_session()
    # HTTP bodies are unframed JSON-RPC objects.
    active.framed = False
    try:
        message = parse_jsonrpc(body)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        err = {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32700, "message": f"parse error: {exc}"},
        }
        return (
            400,
            encode_jsonrpc_message(err),
            {"content-type": "application/json"},
        )
    result = active.handle_message(message)
    payload = encode_jsonrpc_message(result.client_message)
    return 200, payload, {"content-type": "application/json"}


def build_asgi_app(gateway: McpGateway) -> Callable[..., Any]:
    """Minimal ASGI app: POST /mcp → mediated JSON-RPC; GET /ops → summary."""

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return
        path = scope.get("path", "/")
        method = scope.get("method", "GET")

        if method == "GET" and path in {"/ops", "/v1/gateway/ops"}:
            body = json.dumps(gateway.ops_summary()).encode("utf-8")
            await _send_http(send, 200, body, "application/json")
            return

        if method == "POST" and path in {"/mcp", "/"}:
            chunks: list[bytes] = []
            while True:
                event = await receive()
                if event["type"] == "http.request":
                    chunks.append(event.get("body", b""))
                    if not event.get("more_body"):
                        break
            status, body, headers = handle_http_jsonrpc(gateway, b"".join(chunks))
            await _send_http(
                send,
                status,
                body,
                headers.get("content-type", "application/json"),
            )
            return

        await _send_http(send, 404, b'{"error":"not found"}', "application/json")

    return app


async def _send_http(
    send: Any,
    status: int,
    body: bytes,
    content_type: str,
) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", content_type.encode("ascii")),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
