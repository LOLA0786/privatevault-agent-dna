"""What a gateway listener accepts before it acts.

The MCP proxy and the HTTPS egress listener act with the agent's key and the
operator's upstream credentials. Bound to loopback, they were still reachable
from any web page and from a DNS-rebound name: a cross-site POST with
Content-Type text/plain needs no CORS preflight, and nothing checked Host,
Origin or Content-Type (audit finding, core A). Every request must now:

- name an allowed Host: the listener's own address, a loopback name on its
  port, or a host listed in PV_GATEWAY_ALLOWED_HOSTS (comma-separated
  host:port), so a rebound name is refused;
- carry no Origin header: browsers send one on cross-site and on non-GET
  requests, and the MCP and SDK clients this gateway serves do not;
- fit within PV_GATEWAY_MAX_BODY_BYTES (4 MiB unless set).

The MCP endpoint also requires a JSON body, as JSON-RPC always is. The egress
endpoint does not, because some upstream APIs take form-encoded bodies; the
Host and Origin checks already refuse a browser there. This does not stop
another process of the same user, which can read the agent's credentials
anyway; a per-listener token is a separate change.
"""

from __future__ import annotations

import os
from typing import Any

DEFAULT_MAX_BODY_BYTES = 4 * 1024 * 1024
_LOOPBACK = ("localhost", "127.0.0.1", "[::1]")


class BodyTooLargeError(Exception):
    """The request body exceeded the listener's cap."""


def header(scope: dict[str, Any], name: bytes) -> str:
    for key, value in scope.get("headers") or []:
        if bytes(key).lower() == name:
            return bytes(value).decode("latin-1")
    return ""


def allowed_hosts(scope: dict[str, Any]) -> frozenset[str]:
    """Host values this listener answers to."""
    server = scope.get("server") or (None, None)
    address, port = server[0], server[1]
    names = set(_LOOPBACK)
    if address:
        names.add(f"[{address}]" if ":" in address else address)
    allowed = {f"{name}:{port}" for name in names} if port else set(names)
    if port in (80, None):
        allowed |= names
    extra = os.environ.get("PV_GATEWAY_ALLOWED_HOSTS", "")
    allowed |= {host.strip() for host in extra.split(",") if host.strip()}
    return frozenset(host.lower() for host in allowed)


def max_body_bytes() -> int:
    raw = os.environ.get("PV_GATEWAY_MAX_BODY_BYTES", "").strip()
    return int(raw) if raw.isdigit() and int(raw) > 0 else DEFAULT_MAX_BODY_BYTES


def refusal(
    scope: dict[str, Any], *, require_json: bool = False
) -> tuple[int, str] | None:
    """(status, reason) for a request this listener must not act on, else None."""
    if header(scope, b"host").strip().lower() not in allowed_hosts(scope):
        return (
            421,
            "this listener does not answer to that Host; list it in PV_GATEWAY_ALLOWED_HOSTS",
        )
    if header(scope, b"origin"):
        return 403, "requests from a browser page are refused"
    if require_json:
        media_type = header(scope, b"content-type").split(";", 1)[0].strip().lower()
        if media_type != "application/json":
            return 415, "this endpoint takes application/json"
    return None


async def read_body(receive: Any, limit: int) -> bytes:
    """The request body, refusing to buffer more than `limit` bytes."""
    chunks: list[bytes] = []
    size = 0
    while True:
        event = await receive()
        if event["type"] == "http.disconnect":
            return b""
        if event["type"] != "http.request":
            continue
        body = event.get("body", b"")
        size += len(body)
        if size > limit:
            raise BodyTooLargeError(size)
        chunks.append(body)
        if not event.get("more_body"):
            return b"".join(chunks)
