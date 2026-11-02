#!/usr/bin/env python3
"""PrivateVault for Claude Code: is the API up when a session starts?

The PreToolUse gate fails closed, so with no PrivateVault running every
shell command, file write, fetch and MCP call is refused. This SessionStart
hook checks GET /health once and, if there is no answer, tells you (and
Claude) how to start it, instead of letting the first refusal be the news.

A server can also be up and still be refused on every call: one that does
not sign its decisions, or signs with another key than the pinned one (the
docker compose quickstart on port 8000 is the usual case). When a key is
pinned, the hook reads that from the server's own manifest (GET /) and says
so, with the fix. If the manifest cannot be read, it stays silent.

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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pv_pretool import pinned_key  # noqa: E402  (beside this file)

START = "uvx --from git+https://github.com/LOLA0786/privatevault-agent-dna pv up"
TIMEOUT_S = 2.0


def base_url() -> str:
    return os.environ.get("PV_ENFORCE_URL", "http://127.0.0.1:8000").rstrip("/")


def _opener(base: str) -> urllib.request.OpenerDirector:
    host = urllib.parse.urlsplit(base).hostname or ""
    if host in {"localhost", "127.0.0.1", "::1"}:
        return urllib.request.build_opener(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener()


def healthy(base: str) -> tuple[bool, str]:
    opener = _opener(base)
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
    return _notice(text)


def manifest(base: str) -> dict | None:
    """The server's own description (GET /), or None if it cannot be read."""
    try:
        with _opener(base).open(f"{base}/", timeout=TIMEOUT_S) as response:
            data = json.loads(response.read(1 << 20))
    except (urllib.error.URLError, OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def signing_problem(base: str) -> str | None:
    """Why the gate will refuse every answer from the PrivateVault at `base`
    although it is up, or None. Told only when a key is pinned and the
    server's manifest says it signs with no key or with another one."""
    key, _ = pinned_key()
    if not key:
        return None  # nothing pinned, or unreadable: the gate says so per call
    info = manifest(base)
    if info is None or "PrivateVault" not in str(info.get("product", "")):
        return None
    signing = info.get("signing")
    if not isinstance(signing, dict) or not signing.get("public_key"):
        return "it does not sign decisions"
    if str(signing["public_key"]).lower() != key.hex():
        return "it signs with a different key from the one the plugin pins"
    return None


def unsigned_message(base: str, problem: str) -> dict:
    parts = urllib.parse.urlsplit(base)
    local = (parts.hostname or "") in {"localhost", "127.0.0.1", "::1"}
    port = parts.port or 80
    start = START if port == 8000 else f"{START} --port {port}"
    fix = (
        f"pv up always signs with the pinned key, so this is another server; "
        f"the docker compose quickstart is the usual one (docker ps --filter "
        f"publish={port}). Stop it, then start PrivateVault in another "
        f"terminal: {start}"
        if local
        else "Check that PV_ENFORCE_URL points at the PrivateVault whose key is pinned"
    )
    return _notice(
        f"PrivateVault at {base} is up, but {problem}, so the plugin will "
        f"refuse every shell command, file write, fetch and MCP tool call. {fix}"
    )


def _notice(text: str) -> dict:
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
    problem = signing_problem(base)
    if problem:
        json.dump(unsigned_message(base, problem), sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
