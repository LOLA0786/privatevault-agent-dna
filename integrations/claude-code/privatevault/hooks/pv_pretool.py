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
               (names are resolved; the worst address wins)
    touches    zones a shell command names (privatevault, claude-config,
               git-internals)

    allow             -> no output: Claude Code's own permission rules apply
                         as usual (PrivateVault only ever adds restrictions)
    require_approval  -> "ask": Claude Code asks you before running it,
                         but only in a mode where a person is asked
                         (default, plan); in any other mode (auto,
                         bypassPermissions, acceptEdits, ...) an "ask" could
                         be approved with no one looking, so it is "deny"
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
    PV_DECISION_KEY  the API's Ed25519 public key (64 hex). An "allow" or
                     "ask" counts only if the decision record is signed by
                     that key and names this exact call; anything else is
                     refused. Default: PV_HOME/decision-key.pub, which pv up
                     writes. Neither: every call is refused (ADR 0038).
    PV_ALLOW_UNSIGNED  "1": with no key pinned, accept unsigned answers
                     (the old behaviour; for a server that cannot sign)

Every call carries input_sha256, the digest of Claude Code's whole tool
input (a file's new content, an edit's text, every MCP argument), so a
signed decision names those exact bytes. MCP and other tool inputs are sent
whole; one larger than 256 KiB is refused rather than cut to a preview.
    PV_ALLOW_INSECURE_URL  "1": allow a plain-http PV_ENFORCE_URL that is
                     not on this machine (otherwise refused: a forged
                     "allow" could come from anyone on the path)

Standard library only, so it runs wherever python3 does.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pv_ed25519  # noqa: E402  (beside this file; standard library only)

MAX_INPUT_BYTES = 262_144  # whole MCP/other tool input sent to PrivateVault
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
        return f"mcp.{server}.{tool}", dict(tool_input)
    return f"tool.{tool_name}", dict(tool_input)


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


# Proxies with "fake-IP" DNS (Clash, Surge and similar, common on laptops)
# answer every name with an address from the benchmarking range 198.18.0.0/15
# and forward the connection to the real host. A name resolving there is
# classed public; a URL written with such an address is still private
# (retest 2026-10-24).
FAKE_IP_NET = ipaddress.ip_network("198.18.0.0/15")

# Worst first: a name is classed by the worst address it resolves to.
_CLASS_RANK = ("metadata", "link-local", "loopback", "private", "public")
DNS_TIMEOUT_S = 2.0


def _resolve(host: str) -> list[str]:
    """The addresses a name resolves to now, or [] if it does not resolve
    within DNS_TIMEOUT_S."""
    found: list[str] = []

    def run() -> None:
        try:
            for info in socket.getaddrinfo(host, None):
                found.append(str(info[4][0]).split("%", 1)[0])
        except (OSError, UnicodeError, ValueError):
            pass

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(DNS_TIMEOUT_S)
    return list(dict.fromkeys(found)) if not worker.is_alive() else []


def host_class(url: str) -> str:
    """What kind of host a URL names. A name is resolved and classed by the
    worst address it points to, so a public name for 169.254.169.254 is
    metadata (red team retest: DNS). A name that does not resolve is
    classed by its suffix."""
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
    classes = {
        "public" if a in FAKE_IP_NET else _ip_class(a)
        for a in map(_ip, _resolve(host))
        if a is not None
    }
    for worst in _CLASS_RANK:
        if worst in classes:
            return worst
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


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), default=str
    ).encode()


def input_sha256(tool_input: dict[str, Any]) -> str:
    """Digest of Claude Code's whole tool input: what a signed decision for
    this call is bound to (ADR 0038)."""
    return hashlib.sha256(_canonical(tool_input)).hexdigest()


def input_too_large(capability: str, tool_input: dict[str, Any]) -> str | None:
    """Why this input is refused before asking PrivateVault, or None. MCP and
    other tools send their whole input; a preview would let the hidden part
    through unchecked."""
    if capability.split(".", 1)[0] not in ("mcp", "tool"):
        return None
    size = len(_canonical(tool_input))
    if size <= MAX_INPUT_BYTES:
        return None
    return (
        f"PrivateVault refused this call: its input is {size} bytes, over the "
        f"{MAX_INPUT_BYTES}-byte limit the policy can check whole"
    )


MAX_CLOCK_SKEW_S = 600


def pinned_key() -> tuple[bytes | None, str]:
    """(public key, where it came from); (None, "") when none is pinned,
    (b"", source) when one is configured but unreadable or malformed."""
    raw = os.environ.get("PV_DECISION_KEY", "").strip()
    source = "PV_DECISION_KEY"
    if not raw:
        home = os.environ.get("PV_HOME") or "~/.privatevault"
        source = os.path.join(os.path.expanduser(home), "decision-key.pub")
        try:
            with open(source, encoding="ascii") as fh:
                raw = fh.read().strip()
        except FileNotFoundError:
            return None, ""
        except (OSError, ValueError):
            return b"", source
    try:
        key = bytes.fromhex(raw)
    except ValueError:
        return b"", source
    return (key, source) if len(key) == 32 else (b"", source)


def _record_hash(record: dict[str, Any]) -> str:
    payload = {k: v for k, v in record.items() if k != "record_hash"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _arguments_digest(arguments: dict[str, Any]) -> str:
    canonical = json.dumps(
        arguments, sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def signature_problem(  # noqa: C901 - one check per line of the contract
    body: dict[str, Any], payload: dict[str, Any], key: bytes
) -> str | None:
    """Why this answer is not a decision signed by ``key`` for exactly this
    call, or None if it is (ADR 0035)."""
    record, envelope = body.get("record"), body.get("envelope")
    if not isinstance(record, dict) or not isinstance(envelope, dict):
        return "the answer carries no signed decision record"
    record_hash = record.get("record_hash")
    if not isinstance(record_hash, str) or _record_hash(record) != record_hash:
        return "the decision record does not match its hash"
    if (
        envelope.get("algorithm") != "Ed25519"
        or envelope.get("signed_hash") != record_hash
    ):
        return "the signature is not over this record"
    if str(envelope.get("public_key", "")).lower() != key.hex():
        return "the record is signed by a key other than the pinned one"
    try:
        signature = bytes.fromhex(str(envelope.get("signature", "")))
    except ValueError:
        return "the signature is malformed"
    if not pv_ed25519.verify(key, record_hash.encode(), signature):
        return "the signature does not verify"
    expected = {
        "agent_id": payload.get("agent_id"),
        "capability": payload.get("capability"),
        "request_id": payload.get("request_id"),
        "arguments_digest": _arguments_digest(payload.get("arguments") or {}),
    }
    for name, value in expected.items():
        if record.get(name) != value:
            return f"the signed record is for a different call ({name})"
    if body.get("decision") not in (None, record.get("decision")):
        return "the answer's decision differs from the signed record's"
    stamp = record.get("timestamp")
    if not isinstance(stamp, (int, float)) or abs(stamp - time.time()) > (
        MAX_CLOCK_SKEW_S
    ):
        return "the signed record is not from now"
    return None


def checked_verdict(
    status: int | None, body: dict[str, Any] | str, payload: dict[str, Any]
) -> tuple[str | None, str]:
    """verdict(), but an allow or ask must be a signed decision for this call
    when a key is pinned."""
    decision, reason = verdict(status, body)
    if decision == "deny" or not isinstance(body, dict):
        return decision, reason
    key, source = pinned_key()
    if key is None:
        if os.environ.get("PV_ALLOW_UNSIGNED", "") == "1":
            return decision, reason
        return "deny", (
            "no PrivateVault decision key is pinned, so this answer cannot be "
            "checked; refusing. Set PV_DECISION_KEY to the API's public key, "
            "or run pv up, which writes ~/.privatevault/decision-key.pub"
        )
    if not key:
        return "deny", f"PrivateVault's pinned key ({source}) is unreadable; refusing"
    problem = signature_problem(body, payload, key)
    if problem is not None:
        return "deny", f"PrivateVault's answer failed the signature check: {problem}"
    return decision, reason


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


# Permission modes in which Claude Code shows a hook's "ask" to a person.
# Anything else (auto mode's classifier, bypassPermissions, acceptEdits,
# a mode added later) may approve it with no one looking (ADR 0037).
PROMPTING_MODES = frozenset({"default", "plan"})


def needs_a_person(
    decision: str | None, reason: str, mode: object
) -> tuple[str | None, str]:
    """Turn an "ask" into "deny" when Claude Code would not show it to a
    person. An event without a mode (older Claude Code, which always asks)
    keeps the "ask"."""
    if decision != "ask" or mode is None or mode in PROMPTING_MODES:
        return decision, reason
    return "deny", (
        f"{reason}. Claude Code is in {mode!r} mode, where this approval could "
        "be given without you seeing it, so it is refused. To approve it, "
        "switch to default mode (shift+tab) and ask again."
    )


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except ValueError:
        event = {}
    tool_name = str(event.get("tool_name", ""))
    tool_input = event.get("tool_input") or {}
    if not tool_name or not isinstance(tool_input, dict):
        decision, reason = "deny", "PrivateVault gate received an unreadable tool call"
    elif too_large := input_too_large(
        capability_for(tool_name, tool_input)[0], tool_input
    ):
        decision, reason = "deny", too_large
    else:
        capability, arguments = capability_for(tool_name, tool_input)
        cwd = event.get("cwd") if isinstance(event.get("cwd"), str) else os.getcwd()
        arguments = classify(capability, arguments, cwd)
        arguments["input_sha256"] = input_sha256(tool_input)
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
        # Every call has its own request id, which the signed record must name.
        payload["request_id"] = str(event.get("tool_use_id") or uuid.uuid4())
        decision, reason = checked_verdict(*decide(payload), payload)
        decision, reason = needs_a_person(
            decision, reason, event.get("permission_mode")
        )
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
