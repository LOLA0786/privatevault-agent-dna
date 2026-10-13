"""One-line structured events for every process in the demo.

    12:01:33.412 privatevault DECIDE     require_approval decision=8a22… policy=above-approval-threshold

Format: time, service, event, then ``key=value`` fields. Colour only when
stdout is a terminal and ``NO_COLOR`` is unset. No dependencies.
"""

from __future__ import annotations

import os
import sys
import threading
from datetime import UTC, datetime
from typing import Any

GREEN, RED, YELLOW, CYAN, DIM, BOLD, RESET = (
    "\033[32m",
    "\033[31m",
    "\033[33m",
    "\033[36m",
    "\033[2m",
    "\033[1m",
    "\033[0m",
)

GOOD = {"ADMITTED", "allow", "EXECUTED", "APPROVED", "ORDER", "OK", "CREATED"}
BAD = {"REFUSED", "block", "DENIED", "FAIL", "REJECTED", "CONTROL_FAILURE"}
WAIT = {"require_approval", "WAITING", "PENDING"}

_lock = threading.Lock()


def colour_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("PV_LIVE_COLOR", "").lower() in {"1", "always"}:
        return True
    return sys.stdout.isatty()


def short(value: Any, keep: int = 18) -> str:
    text = "-" if value is None else str(value)
    return text if len(text) <= keep + 1 else text[:keep] + "…"


def fmt(service: str, event: str, outcome: str = "", **fields: Any) -> str:
    stamp = datetime.now(UTC).strftime("%H:%M:%S.%f")[:-3]
    use_colour = colour_enabled()
    head = f"{stamp} {service:<12} {event:<10}"
    if use_colour:
        tone = ""
        if outcome in GOOD:
            tone = GREEN
        elif outcome in BAD:
            tone = RED
        elif outcome in WAIT:
            tone = YELLOW
        head = (
            f"{DIM}{stamp}{RESET} {CYAN}{service:<12}{RESET} {BOLD}{event:<10}{RESET}"
        )
        body = f"{tone}{outcome:<18}{RESET}" if outcome else ""
    else:
        body = f"{outcome:<18}" if outcome else ""
    tail = " ".join(f"{k}={v}" for k, v in fields.items() if v is not None)
    return f"{head} {body} {tail}".rstrip()


def log(service: str, event: str, outcome: str = "", **fields: Any) -> None:
    line = fmt(service, event, outcome, **fields)
    with _lock:
        print(line, flush=True)
