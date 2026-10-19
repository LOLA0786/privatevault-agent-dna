"""Per-credential request rate limiting for the HTTP API (DoS hardening).

Off unless the operator sets ``PV_RATE_LIMIT_RPS`` (sustained requests per
second per credential) and optionally ``PV_RATE_LIMIT_BURST`` (bucket size,
default ``2 x RPS``, at least 1). Each credential -- the SHA-256 of the
``X-API-Key`` header, or the client address when no key is sent -- has its
own token bucket, so one noisy or compromised agent cannot starve the
others or the approvers. A request over the limit is refused with ``429``
and ``Retry-After`` before routing, authentication or body parsing, and
never reaches the decision path, so a refusal is never an ALLOW.

Health, readiness and metrics probes are exempt. Buckets live in process
memory and are bounded (least recently used evicted past ``max_keys``); with
several replicas each enforces its own limit, so the effective ceiling is
``replicas x RPS``. A shared limiter (PostgreSQL or the ingress) is the
multi-host answer and is not provided here.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Mapping, MutableMapping
from dataclasses import dataclass
from typing import Any

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

RATE_LIMITED = "RATE_LIMITED"
EXEMPT_PATHS = frozenset({"/ready", "/health", "/healthz", "/metrics"})
RPS_ENV = "PV_RATE_LIMIT_RPS"
BURST_ENV = "PV_RATE_LIMIT_BURST"
MAX_RPS = 100_000.0


@dataclass(frozen=True)
class RateLimit:
    rps: float
    burst: int
    max_keys: int = 10_000


def rate_limit_from_env(env: Mapping[str, str]) -> RateLimit | None:
    """Parse and validate once at startup. Invalid values refuse to start."""
    raw = env.get(RPS_ENV, "").strip()
    if not raw:
        return None
    try:
        rps = float(raw)
    except ValueError as exc:
        raise ValueError(f"{RPS_ENV} must be a number, got {raw!r}") from exc
    if not math.isfinite(rps) or rps <= 0 or rps > MAX_RPS:
        raise ValueError(f"{RPS_ENV} must be in (0, {MAX_RPS:g}], got {raw!r}")
    raw_burst = env.get(BURST_ENV, "").strip()
    try:
        burst = int(raw_burst) if raw_burst else max(1, math.ceil(2 * rps))
    except ValueError as exc:
        raise ValueError(f"{BURST_ENV} must be an integer, got {raw_burst!r}") from exc
    if burst < 1 or burst > 10 * MAX_RPS:
        raise ValueError(f"{BURST_ENV} must be >= 1, got {raw_burst!r}")
    return RateLimit(rps=rps, burst=burst)


class TokenBuckets:
    def __init__(self, limit: RateLimit, clock: Callable[[], float] = time.monotonic):
        self.limit = limit
        self.clock = clock
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._lock = threading.Lock()

    def take(self, key: str) -> float:
        """0.0 if admitted, else seconds until a token is available."""
        now = self.clock()
        lim = self.limit
        with self._lock:
            tokens, last = self._buckets.pop(key, (float(lim.burst), now))
            tokens = min(float(lim.burst), tokens + (now - last) * lim.rps)
            if tokens >= 1.0:
                self._buckets[key] = (tokens - 1.0, now)
                wait = 0.0
            else:
                self._buckets[key] = (tokens, now)
                wait = (1.0 - tokens) / lim.rps
            while len(self._buckets) > lim.max_keys:
                self._buckets.popitem(last=False)
        return wait


def _credential(scope: Scope) -> str:
    for name, value in scope.get("headers", []):
        if name.lower() == b"x-api-key" and value:
            return "k:" + hashlib.sha256(value).hexdigest()[:32]
    client = scope.get("client") or ("unknown", 0)
    return "a:" + str(client[0])


class RateLimitMiddleware:
    """Refuse requests over the per-credential rate with 429."""

    def __init__(
        self, app: ASGIApp, limit: Callable[[], RateLimit | None] | None = None
    ) -> None:
        self.app = app
        self.limit = limit or (lambda: None)
        self._buckets: TokenBuckets | None = None

    def _for(self, limit: RateLimit) -> TokenBuckets:
        if self._buckets is None or self._buckets.limit != limit:
            self._buckets = TokenBuckets(limit)
        return self._buckets

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        limit = self.limit() if scope["type"] == "http" else None
        if limit is None or scope.get("path") in EXEMPT_PATHS:
            await self.app(scope, receive, send)
            return
        wait = self._for(limit).take(_credential(scope))
        if wait <= 0.0:
            await self.app(scope, receive, send)
            return
        body = json.dumps(
            {
                "detail": {
                    "reason_code": RATE_LIMITED,
                    "detail": f"over {limit.rps:g} requests/s for this credential",
                }
            },
            sort_keys=True,
        ).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 429,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    (b"retry-after", str(max(1, math.ceil(wait))).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
