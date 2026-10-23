#!/usr/bin/env python3
"""PrivateVault for Claude Code: is the API up when a session starts?

The PreToolUse gate fails closed, so with no PrivateVault running every
shell command, file write, fetch and MCP call is refused. This SessionStart
hook checks GET /health once and, if there is no answer, tells you (and
Claude) how to start it, instead of letting the first refusal be the news.

It never blocks the session. Same settings as pv_pretool.py
(PV_ENFORCE_URL, PV_FAIL_OPEN). Standard library only.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

START = "uvx --from git+https://github.com/LOLA0786/privatevault-agent-dna pv up"
TIMEOUT_S = 2.0


def base_url() -> str:
    return os.environ.get("PV_ENFORCE_URL", "http://127.0.0.1:8000").rstrip("/")


def healthy(base: str) -> tuple[bool, str]:
    host = urllib.parse.urlsplit(base).hostname or ""
    if host in {"localhost", "127.0.0.1", "::1"}:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    else:
        opener = urllib.request.build_opener()
    try:
        with opener.open(f"{base}/health", timeout=TIMEOUT_S) as response:
            return response.status == 200, f"HTTP {response.status}"
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return False, f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}"


def message(base: str, why: str) -> dict:
    fail_open = os.environ.get("PV_FAIL_OPEN", "") == "1"
    effect = (
        "you will be asked before each one runs"
        if fail_open
        else "they will be refused"
    )
    parts = urllib.parse.urlsplit(base)
    local = (parts.hostname or "") in {"localhost", "127.0.0.1", "::1"}
    port = parts.port or 80
    start = START if port == 8000 else f"{START} --port {port}"
    fix = (
        f"Start it in another terminal: {start}"
        if local
        else "Check that the PrivateVault API is reachable and PV_ENFORCE_URL is right."
    )
    text = (
        f"PrivateVault is not answering at {base} ({why}). Shell commands, file "
        f"writes, fetches and MCP tool calls are checked by PrivateVault, so "
        f"{effect} until it is running. {fix}"
    )
    return {
        "systemMessage": text,
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": text
            + ". If the user asks you to run tools, tell them this first; do not try"
            " to start PrivateVault yourself.",
        },
    }


def main() -> int:
    try:
        json.load(sys.stdin)
    except ValueError:
        pass  # the event's content is not needed
    base = base_url()
    ok, why = healthy(base)
    if not ok:
        json.dump(message(base, why), sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
