"""Per-credential request rate limiting for the HTTP API (DoS hardening).

Off unless the operator sets ``PV_RATE_LIMIT_RPS`` (sustained requests per
second per credential) and optionally ``PV_RATE_LIMIT_BURST`` (bucket size,
default ``2 x RPS``, at least 1). A request over the limit is refused with
``429`` and ``Retry-After`` before routing or body parsing, and never reaches
the decision path, so a refusal is never an ALLOW.

Who gets a bucket: only a *registered* API key earns its own bucket, so one
noisy or compromised agent cannot starve the others or the approvers. A
request with no key, or with a key the registry does not hold, is charged to
its client address. A caller therefore cannot mint fresh buckets by inventing
keys, and junk traffic lives in a separate, bounded address table, so it can
never evict a registered agent's bucket. Behind a proxy every unauthenticated
request shares the proxy's address: stricter, never looser.

Health, readiness and metrics probes are exempt. Buckets live in process
memory; with several replicas each enforces its own limit, so the effective
ceiling is ``replicas x RPS``. A shared limiter (PostgreSQL or the ingress)
is the multi-host answer and is not provided here.
"""

from __future__ import annotations

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


def _api_key(scope: Scope) -> str | None:
    for name, value in scope.get("headers", []):
        if name.lower() == b"x-api-key" and value:
            return value.decode("latin-1")
    return None


def _address(scope: Scope) -> str:
    client = scope.get("client") or ("unknown", 0)
    return str(client[0])


class RateLimitMiddleware:
    """Refuse requests over the per-credential rate with 429.

    ``identify(key)`` returns the registered identity a key belongs to, or
    None; only registered identities get their own bucket (see the module
    docstring). Without it every request is charged to its client address.
    The key itself is never hashed, stored or used as a bucket name."""

    def __init__(
        self,
        app: ASGIApp,
        limit: Callable[[], RateLimit | None] | None = None,
        identify: Callable[[str], str | None] | None = None,
    ) -> None:
        self.app = app
        self.limit = limit or (lambda: None)
        self.identify = identify or (lambda _key: None)
        self._keys: TokenBuckets | None = None
        self._addresses: TokenBuckets | None = None

    def _tables(self, limit: RateLimit) -> tuple[TokenBuckets, TokenBuckets]:
        if self._keys is None or self._addresses is None or self._keys.limit != limit:
            self._keys = TokenBuckets(limit)
            self._addresses = TokenBuckets(limit)
        return self._keys, self._addresses

    def _take(self, limit: RateLimit, scope: Scope) -> float:
        keys, addresses = self._tables(limit)
        key = _api_key(scope)
        identity = self.identify(key) if key is not None else None
        if identity is not None:
            return keys.take("k:" + identity)
        return addresses.take("a:" + _address(scope))

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        limit = self.limit() if scope["type"] == "http" else None
        if limit is None or scope.get("path") in EXEMPT_PATHS:
            await self.app(scope, receive, send)
            return
        wait = self._take(limit, scope)
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
