#!/usr/bin/env python3
"""PrivateVault gate for Claude Code (PreToolUse hook).

Before Claude Code runs a shell command, reads or writes a file, fetches a
URL or calls an MCP tool, this hook asks a PrivateVault API (POST
/v1/decide) whether the action is allowed, and every decision is sealed
into PrivateVault's hash-chained ledger.

With each file path it sends the path's zone, and with each URL the kind
of host, so the policy can tell PrivateVault's own state, Claude Code and
git configuration, credentials and cloud metadata from ordinary work:

    zone       privatevault | claude-config | git-internals | credentials
               | outside-project | project
    host_class metadata | link-local | loopback | private | public | invalid
    touches    zones a shell command names (privatevault, claude-config,
               git-internals)

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
    PV_HOME          PrivateVault's state folder (default ~/.privatevault)
    PV_ALLOW_INSECURE_URL  "1": allow a plain-http PV_ENFORCE_URL that is
                     not on this machine (otherwise refused: a forged
                     "allow" could come from anyone on the path)

Standard library only, so it runs wherever python3 does.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

MAX_ARG_CHARS = 16_384
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
READ_TOOLS = {"Read", "Grep"}
# Same names as agent_dna.shell_guard._SENSITIVE (tests keep them in step).
SENSITIVE = re.compile(
    r"(^|/)(\.env(\.[^/]*)?|\.netrc|\.npmrc|\.pypirc|\.git-credentials|"
    r"id_(rsa|dsa|ecdsa|ed25519)[^/]*|\.?credentials(\.[^/]*)?|[^/]*\.(pem|key|p12|pfx))$"
    r"|(^|/)\.(ssh|aws|gnupg|kube|docker)(/|$)"
    r"|^/proc/[^/]+/environ$"
    r"|secret",
    re.IGNORECASE,
)
METADATA_HOSTS = {
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "instance-data.ec2.internal",
}
METADATA_IPS = {"169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
START = "uvx --from git+https://github.com/LOLA0786/privatevault-agent-dna pv up"


def base_url() -> str:
    return os.environ.get("PV_ENFORCE_URL", "http://127.0.0.1:8000").rstrip("/")


def start_hint() -> str:
    """How to start the API, when it is configured on this machine."""
    parts = urllib.parse.urlsplit(base_url())
    if (parts.hostname or "") not in LOCAL_HOSTS:
        return ""
    port = parts.port or 80
    return " To start PrivateVault on this machine: " + (
        START if port == 8000 else f"{START} --port {port}"
    )


def capability_for(tool_name: str, tool_input: dict[str, Any]) -> tuple[str, dict]:
    """Map a Claude Code tool call to a PrivateVault capability and arguments."""
    if tool_name == "Bash":
        return "shell.exec", {"command": str(tool_input.get("command", ""))}
    if tool_name in READ_TOOLS:
        path = tool_input.get("file_path") or tool_input.get("path") or "."
        args = {"path": str(path), "tool": tool_name}
        if tool_name == "Grep":
            args["pattern"] = str(tool_input.get("pattern", ""))[:1024]
            if tool_input.get("glob"):
                args["glob"] = str(tool_input["glob"])[:1024]
        return "fs.read", args
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


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _candidates(path: str, cwd: str) -> list[str]:
    """The path as written (normalised) and with symlinks resolved."""
    p = os.path.expanduser(path)
    if not os.path.isabs(p):
        p = os.path.join(cwd, p)
    out = [os.path.normpath(p)]
    try:
        out.append(os.path.realpath(p))
    except (OSError, ValueError):
        pass
    return list(dict.fromkeys(out))


def _roots(path: str) -> list[str]:
    p = os.path.expanduser(path)
    return list(dict.fromkeys([os.path.normpath(p), os.path.realpath(p)]))


def zone_of(path: str, cwd: str) -> str:
    """Where a file path points, for the policy (red team 2026-10-23, F2,
    F7, F12): PrivateVault's own state, Claude Code or git configuration
    (both can make later commands run code), credentials, outside the
    project, or the project."""
    # the configured home, and the default one whatever PV_HOME says
    pv_home = _roots("~/.privatevault")
    if os.environ.get("PV_HOME"):
        pv_home += _roots(os.environ["PV_HOME"])
    claude_home = _roots(os.environ.get("CLAUDE_CONFIG_DIR") or "~/.claude")
    project = _roots(cwd)
    cands = _candidates(path, cwd)
    if any(_under(c, r) for c in cands for r in pv_home):
        return "privatevault"
    for c in cands:
        if any(_under(c, r) for r in claude_home):
            return "claude-config"
        for root in project:
            if _under(c, os.path.join(root, ".claude")) or c == os.path.join(
                root, ".mcp.json"
            ):
                return "claude-config"
        if ".git" in c.split(os.sep)[:-1]:
            return "git-internals"  # hooks and config run code on later commands
    if any(SENSITIVE.search(c) for c in cands):
        return "credentials"
    # outside if the path as written or its real target leaves the project
    if not all(any(_under(c, r) for r in project) for c in cands):
        return "outside-project"
    return "project"


def _ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:  # 2852039166, 0xa9fea9fe, 0251.0376.0251.0376: forms curl accepts
            ip = ipaddress.ip_address(socket.inet_aton(host))
        except (OSError, ValueError):
            return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def _ip_class(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if str(ip) in METADATA_IPS:
        return "metadata"
    if ip.is_link_local:
        return "link-local"
    if ip.is_loopback or ip.is_unspecified:
        return "loopback"
    if ip.is_private or ip.is_reserved or ip.is_multicast:
        return "private"
    return "public"


def host_class(url: str) -> str:
    """What kind of host a URL names, without resolving DNS."""
    try:
        host = (urllib.parse.urlsplit(url).hostname or "").rstrip(".").lower()
    except ValueError:
        return "invalid"
    if not host:
        return "invalid"
    if host in METADATA_HOSTS:
        return "metadata"
    if host == "localhost" or host.endswith(".localhost"):
        return "loopback"
    ip = _ip(host)
    if ip is not None:
        return _ip_class(ip)
    return "private" if host.endswith((".internal", ".local", ".lan")) else "public"


def touches(command: str) -> list[str]:
    """Zones a shell command names by path."""
    found = []
    if ".privatevault" in command or (
        os.environ.get("PV_HOME") and os.environ["PV_HOME"] in command
    ):
        found.append("privatevault")
    if re.search(r"\.claude(/|\b)|\.mcp\.json", command):
        found.append("claude-config")
    if re.search(r"\.git/(hooks|config|info)", command):
        found.append("git-internals")
    return found


def classify(capability: str, arguments: dict, cwd: str) -> dict:
    """Arguments plus what the policy needs to know about them."""
    out = dict(arguments)
    if capability in {"fs.read", "fs.write"} and isinstance(out.get("path"), str):
        out["zone"] = zone_of(out["path"], cwd)
    elif capability == "net.fetch" and isinstance(out.get("url"), str):
        out["host_class"] = host_class(out["url"])
    elif capability == "shell.exec" and isinstance(out.get("command"), str):
        out["touches"] = touches(out["command"])
    return out


def _bounded(value: Any) -> dict:
    text = json.dumps(value, sort_keys=True, default=str)
    if len(text) <= MAX_ARG_CHARS:
        return value if isinstance(value, dict) else {"value": value}
    return {"truncated": True, "preview": text[:MAX_ARG_CHARS]}


def url_is_trustworthy(base: str) -> bool:
    """https anywhere, or http on this machine (red team 2026-10-23, F13)."""
    parts = urllib.parse.urlsplit(base)
    if parts.scheme == "https":
        return True
    if parts.scheme == "http" and (parts.hostname or "") in LOCAL_HOSTS:
        return True
    return os.environ.get("PV_ALLOW_INSECURE_URL", "") == "1"


def decide(payload: dict[str, Any]) -> tuple[int | None, dict[str, Any] | str]:
    """POST /v1/decide. Returns (status, body) or (None, error text)."""
    base = base_url()
    if not url_is_trustworthy(base):
        return None, (
            f"PV_ENFORCE_URL {base} is plain http to another machine; a forged "
            "answer could allow anything. Use https, or set PV_ALLOW_INSECURE_URL=1"
        )
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
    if host in LOCAL_HOSTS:
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
            "." if fail_open else "; refusing (set PV_FAIL_OPEN=1 to be asked instead)."
        ) + start_hint()
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
        cwd = event.get("cwd") if isinstance(event.get("cwd"), str) else os.getcwd()
        arguments = classify(capability, arguments, cwd)
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
