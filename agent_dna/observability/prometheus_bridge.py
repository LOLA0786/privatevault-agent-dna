"""Optional Prometheus instrumentation for the decide path.

prometheus_client is a soft dependency: when absent, record() is a no-op and
the HTTP fallback in api.server still emits text exposition from in-process
counters. Metrics never authorize.
"""

from __future__ import annotations

from typing import Any

_PROM: dict[str, Any] | None = None
_IMPORT_TRIED = False


def _prom() -> dict[str, Any] | None:
    global _PROM, _IMPORT_TRIED
    if _IMPORT_TRIED:
        return _PROM
    _IMPORT_TRIED = True
    try:
        from prometheus_client import Counter, Gauge, Histogram
    except ImportError:
        _PROM = None
        return None

    _PROM = {
        "decisions": Counter(
            "pv_decisions_total",
            "Decisions recorded by verdict",
            ["verdict"],
        ),
        "blocks": Counter(
            "pv_blocks_total",
            "Blocked decisions by reason",
            ["reason"],
        ),
        "latency": Histogram(
            "pv_decide_latency_seconds",
            "Wall time of POST /v1/decide",
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
        ),
        "ready": Gauge(
            "pv_ready",
            "1 when the process reports ready (store open)",
        ),
    }
    return _PROM


def record_decision(verdict: str, reason: str = "") -> None:
    prom = _prom()
    if prom is None:
        return
    prom["decisions"].labels(verdict=verdict).inc()
    if verdict.lower() == "block":
        label = (reason or "unspecified")[:80]
        prom["blocks"].labels(reason=label).inc()


def observe_decide_latency(seconds: float) -> None:
    prom = _prom()
    if prom is None:
        return
    prom["latency"].observe(max(0.0, seconds))


def set_ready(ready: bool) -> None:
    prom = _prom()
    if prom is None:
        return
    prom["ready"].set(1 if ready else 0)


def generate_latest() -> tuple[bytes, str] | None:
    """Return (body, content_type) or None if prometheus_client missing."""
    if _prom() is None:
        return None
    from prometheus_client import CONTENT_TYPE_LATEST
    from prometheus_client import generate_latest as _gen

    return _gen(), CONTENT_TYPE_LATEST
