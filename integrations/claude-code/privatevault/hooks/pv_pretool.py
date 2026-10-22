#!/usr/bin/env python3
"""PrivateVault gate for Claude Code (PreToolUse hook).

Before Claude Code runs a shell command, writes a file, fetches a URL or
calls an MCP tool, this hook asks a PrivateVault API (POST /v1/decide)
whether the action is allowed, and every decision is sealed into
PrivateVault's hash-chained ledger.

    allow             -> no output: Claude Code's own permission rules apply
                         as usual (PrivateVault only ever adds restrictions)
    require_approval  -> "ask": Claude Code asks you before running it
    block             -> "deny": the tool call does not run; Claude sees why
    API unreachable   -> "deny" (fail closed), or "ask" with PV_FAIL_OPEN=1

Settings (environment):
    PV_ENFORCE_URL   PrivateVault API base URL   (default http://127.0.0.1:8000)
    PV_API_KEY       API key, sent as X-API-Key  (optional for a local
                     server started with PV_ALLOW_NO_AUTH=1)
    PV_AGENT_ID      agent id for decisions      (default claude-code)
    PV_FAIL_OPEN     "1": ask instead of deny when the API cannot answer
    PV_TIMEOUT_S     seconds to wait for a decision (default 8)

Standard library only, so it runs wherever python3 does.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

MAX_ARG_CHARS = 16_384
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}


def capability_for(tool_name: str, tool_input: dict[str, Any]) -> tuple[str, dict]:
    """Map a Claude Code tool call to a PrivateVault capability and arguments."""
    if tool_name == "Bash":
        return "shell.exec", {"command": str(tool_input.get("command", ""))}
    if tool_name in WRITE_TOOLS:
        path = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        return "fs.write", {"path": str(path), "tool": tool_name}
    if tool_name == "WebFetch":
        return "net.fetch", {"url": str(tool_input.get("url", ""))}
    if tool_name.startswith("mcp__"):
        parts = tool_name.split("__", 2)
        server = parts[1] if len(parts) > 1 else "unknown"
        tool = parts[2] if len(parts) > 2 else "unknown"
        return f"mcp.{server}.{tool}", _bounded(tool_input)
    return f"tool.{tool_name}", _bounded(tool_input)


def _bounded(value: Any) -> dict:
    text = json.dumps(value, sort_keys=True, default=str)
    if len(text) <= MAX_ARG_CHARS:
        return value if isinstance(value, dict) else {"value": value}
    return {"truncated": True, "preview": text[:MAX_ARG_CHARS]}


def decide(payload: dict[str, Any]) -> tuple[int | None, dict[str, Any] | str]:
    """POST /v1/decide. Returns (status, body) or (None, error text)."""
    base = os.environ.get("PV_ENFORCE_URL", "http://127.0.0.1:8000").rstrip("/")
    headers = {"Content-Type": "application/json"}
    key = os.environ.get("PV_API_KEY", "").strip()
    if key:
        headers["X-API-Key"] = key
    request = urllib.request.Request(
        f"{base}/v1/decide",
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    timeout = float(os.environ.get("PV_TIMEOUT_S", "8"))
    # A local PrivateVault is reached directly, never through a proxy.
    host = urllib.parse.urlsplit(base).hostname or ""
    if host in {"localhost", "127.0.0.1", "::1"}:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    else:
        opener = urllib.request.build_opener()
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"{}")
        except ValueError:
            return exc.code, {}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _reason(body: dict[str, Any]) -> str:
    detail = body.get("detail")
    if isinstance(detail, dict):
        return str(detail.get("detail") or detail.get("reason_code") or detail)
    reason = body.get("reason") or detail or "no reason given"
    record = body.get("record") or {}
    ref = record.get("decision_id")
    return f"{reason} (decision {ref})" if ref else str(reason)


def verdict(status: int | None, body: dict[str, Any] | str) -> tuple[str | None, str]:
    """(permissionDecision or None for 'no opinion', reason)."""
    fail_open = os.environ.get("PV_FAIL_OPEN", "") == "1"
    if status is None or not isinstance(body, dict):
        reason = f"PrivateVault did not answer ({body})"
        return ("ask" if fail_open else "deny"), reason + (
            "" if fail_open else "; refusing (set PV_FAIL_OPEN=1 to be asked instead)"
        )
    decision = str(
        body.get("decision") or (body.get("record") or {}).get("decision") or ""
    )
    if status == 200 and decision == "allow":
        return None, _reason(body)
    if status == 202 or decision == "require_approval":
        return "ask", "PrivateVault requires approval: " + _reason(body)
    if status == 403 or decision == "block":
        return "deny", "PrivateVault blocked this action: " + _reason(body)
    reason = f"PrivateVault answered HTTP {status}: {_reason(body)}"
    return ("ask" if fail_open else "deny"), reason


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except ValueError:
        event = {}
    tool_name = str(event.get("tool_name", ""))
    tool_input = event.get("tool_input") or {}
    if not tool_name or not isinstance(tool_input, dict):
        decision, reason = "deny", "PrivateVault gate received an unreadable tool call"
    else:
        capability, arguments = capability_for(tool_name, tool_input)
        payload = {
            "agent_id": os.environ.get("PV_AGENT_ID", "claude-code"),
            "capability": capability,
            "timestamp": time.time(),
            "arguments": arguments,
            "context": {
                "source": "claude-code",
                "tool_name": tool_name,
                "session_id": event.get("session_id"),
                "cwd": event.get("cwd"),
            },
        }
        tool_use_id = event.get("tool_use_id")
        if tool_use_id:
            payload["request_id"] = str(tool_use_id)
        decision, reason = verdict(*decide(payload))
    if decision is not None:
        json.dump(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": decision,
                    "permissionDecisionReason": reason,
                }
            },
            sys.stdout,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
