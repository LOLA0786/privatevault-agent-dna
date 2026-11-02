"""`pv doctor`: check that Claude Code, the plugin and PrivateVault agree.

Each check prints one line, ok / warn / FAIL / skip, with what it found and,
when it is not ok, the one thing to do. The command changes nothing and writes
nothing: it reads the state folder and Claude Code's settings, asks the server
two read-only questions (GET /health and GET /), and looks at the port, the
disk and the installed plugin. Exit status is 1 when any check FAILs.

The checks are the ways a first run goes wrong:

  keys      the pinned public key is missing, unreadable, or not signing.key's
  server    nothing answers at PV_ENFORCE_URL
  signing   something answers but does not sign, or signs with another key,
            so the plugin refuses every tool call (the docker compose
            quickstart on port 8000 is the usual cause)
  exposure  the port also answers on a network address, not only this machine
  plugin    the installed hook is not this checkout's
  mode      Claude Code is set to a mode where approvals become refusals
  disk      too little space left for the ledger
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import socket
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_dna.quickstart import PUBLIC_KEY_FILE, is_loopback, read_signing_key

DEFAULT_URL = "http://127.0.0.1:8000"
# The modes in which Claude Code shows a person the approval prompt. Kept in
# step with PROMPTING_MODES in the plugin's pv_pretool.py (a test checks it).
PROMPTING_MODES = frozenset({"default", "plan"})
TIMEOUT_S = 2.0
DISK_WARN = 1 << 30  # 1 GiB
DISK_FAIL = 100 << 20  # 100 MiB
CHECKOUT = Path(__file__).resolve().parents[2]
CHECKOUT_HOOK = (
    CHECKOUT
    / "integrations"
    / "claude-code"
    / "privatevault"
    / "hooks"
    / "pv_pretool.py"
)
# How to run pv here: from a checkout it is not on PATH unless installed.
PV = "uv run pv" if CHECKOUT_HOOK.is_file() else "pv"


@dataclass(frozen=True)
class Finding:
    status: str  # "ok", "warn", "FAIL" or "skip"
    name: str
    detail: str


Fetch = Callable[[str], "tuple[int | None, Any, str]"]


def get_json(url: str, timeout: float = TIMEOUT_S) -> tuple[int | None, Any, str]:
    """(HTTP status, parsed JSON or None, error text). Loopback URLs bypass
    any proxy, as the plugin's hook does."""
    host = urllib.parse.urlsplit(url).hostname or ""
    handlers = [urllib.request.ProxyHandler({})] if is_loopback(host) else []
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(url, timeout=timeout) as response:
            raw = response.read(1 << 20)
            status = response.status
    except urllib.error.HTTPError as exc:
        return exc.code, None, f"HTTP {exc.code}"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return None, None, f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}"
    try:
        return status, json.loads(raw), ""
    except ValueError:
        return status, None, "not JSON"


def start_command(url: str) -> str:
    port = urllib.parse.urlsplit(url).port or 8000
    return f"{PV} up" + ("" if port == 8000 else f" --port {port}")


def short(key: str) -> str:
    return f"{key[:8]}..." if len(key) > 8 else key


def check_keys(home: Path) -> tuple[Finding, str | None]:
    """The key the plugin pins, and whether it is signing.key's."""
    raw = os.environ.get("PV_DECISION_KEY", "").strip()
    source = "PV_DECISION_KEY"
    if not raw:
        source = str(home / PUBLIC_KEY_FILE)
        try:
            raw = (home / PUBLIC_KEY_FILE).read_text(encoding="ascii").strip()
        except FileNotFoundError:
            return (
                Finding(
                    "FAIL",
                    "keys",
                    f"no pinned key at {source}, so the plugin refuses every "
                    f"answer; run {PV} up once to create it",
                ),
                None,
            )
        except (OSError, ValueError) as exc:
            return Finding("FAIL", "keys", f"cannot read {source}: {exc}"), None
    try:
        valid = len(bytes.fromhex(raw)) == 32
    except ValueError:
        valid = False
    if not valid:
        return (
            Finding("FAIL", "keys", f"{source} is not a 64-hex Ed25519 public key"),
            None,
        )
    pinned = raw.lower()
    signing = read_signing_key(home)
    if signing is None:
        return (
            Finding(
                "warn",
                "keys",
                f"pinned key {short(pinned)} ({source}); no signing.key in {home}, "
                f"so it can only be checked against the server",
            ),
            pinned,
        )
    if signing[1].lower() != pinned:
        return (
            Finding(
                "FAIL",
                "keys",
                f"{source} pins {short(pinned)} but signing.key is "
                f"{short(signing[1])}; run {PV} up, which rewrites the pinned key",
            ),
            pinned,
        )
    return Finding("ok", "keys", f"pinned key {short(pinned)} is signing.key's"), pinned


def check_server(url: str, fetch: Fetch = get_json) -> tuple[Finding, Any]:
    """Whether anything answers, and the service manifest from GET /."""
    status, _, why = fetch(f"{url}/health")
    if status != 200:
        return (
            Finding(
                "FAIL",
                "server",
                f"nothing healthy at {url} ({why or f'HTTP {status}'}); "
                f"start it in another terminal: {start_command(url)}",
            ),
            None,
        )
    _, manifest, _ = fetch(f"{url}/")
    return Finding("ok", "server", f"{url} is up"), manifest


def check_signing(url: str, manifest: Any, pinned: str | None) -> Finding:
    """Whether the server signs decisions with the key the plugin pins."""
    port = urllib.parse.urlsplit(url).port or 80
    if not isinstance(manifest, dict) or "PrivateVault" not in str(
        manifest.get("product", "")
    ):
        return Finding(
            "FAIL",
            "signing",
            f"something answers at {url}, but GET / is not a PrivateVault "
            f"manifest; find it with: lsof -nP -iTCP:{port} -sTCP:LISTEN",
        )
    signing = manifest.get("signing")
    if not isinstance(signing, dict) or not signing.get("public_key"):
        return Finding(
            "FAIL",
            "signing",
            f"the PrivateVault at {url} does not sign decisions, so the plugin "
            f"refuses every tool call. pv up always signs, so this is another "
            f"server; the docker compose quickstart is the usual one "
            f"(docker ps --filter publish={port}). Stop it, then run "
            f"{start_command(url)}",
        )
    server_key = str(signing["public_key"]).lower()
    if pinned is None:
        return Finding(
            "warn",
            "signing",
            f"the server signs with {short(server_key)}, but no key is pinned to "
            f"check it against",
        )
    if server_key != pinned:
        return Finding(
            "FAIL",
            "signing",
            f"the server signs with {short(server_key)} but the plugin pins "
            f"{short(pinned)}: it is a different PrivateVault (another state "
            f"folder or machine), and the plugin refuses its answers",
        )
    return Finding("ok", "signing", "decisions are signed with the pinned key")


def lan_address() -> str | None:
    """This machine's address on its network, or None. Connecting a UDP
    socket sends nothing; it only picks the outgoing interface."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))  # TEST-NET-1, never routed
            address = probe.getsockname()[0]
    except OSError:
        return None
    if not address or address == "0.0.0.0" or is_loopback(address):
        return None
    return address


def can_connect(address: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((address, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_exposure(
    url: str,
    lan: Callable[[], str | None] = lan_address,
    connect: Callable[[str, int], bool] = can_connect,
) -> Finding:
    """A local PrivateVault should answer only on this machine."""
    parts = urllib.parse.urlsplit(url)
    host, port = parts.hostname or "", parts.port or 80
    if not is_loopback(host):
        return Finding("skip", "exposure", f"{host} is not this machine")
    address = lan()
    if address is None:
        return Finding("skip", "exposure", "no network address to test from")
    if connect(address, port):
        return Finding(
            "warn",
            "exposure",
            f"port {port} also answers on {address}, so other machines on your "
            f"network can reach it. pv up listens only on 127.0.0.1; a docker "
            f"compose port mapping of 8000:8000 listens everywhere "
            f"(use 127.0.0.1:8000:8000)",
        )
    return Finding("ok", "exposure", f"port {port} answers only on this machine")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_plugin(plugins_root: Path, checkout_hook: Path | None = None) -> Finding:
    """Whether Claude Code has the plugin, and whether it is this checkout's."""
    installed = (
        sorted(
            p for p in plugins_root.rglob("pv_pretool.py") if p.parent.name == "hooks"
        )
        if plugins_root.is_dir()
        else []
    )
    if not installed:
        return Finding(
            "warn",
            "plugin",
            f"no PrivateVault plugin under {plugins_root} (fine if you load it "
            f"another way, such as --plugin-dir)",
        )
    if checkout_hook is None or not checkout_hook.is_file():
        return Finding("ok", "plugin", f"installed: {installed[-1].parent.parent}")
    want = _sha256(checkout_hook)
    if any(_sha256(p) == want for p in installed):
        return Finding("ok", "plugin", "the installed hook is this checkout's")
    return Finding(
        "warn",
        "plugin",
        f"none of the {len(installed)} installed hook(s) under {plugins_root} "
        f"match this checkout; update the plugin so the hook and the server "
        f"come from the same version",
    )


def check_mode(settings_files: list[Path]) -> Finding:
    """A default mode in which approvals cannot reach a person. The files are
    in precedence order; the first one that sets defaultMode decides."""
    for path in settings_files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        permissions = data.get("permissions") if isinstance(data, dict) else None
        mode = permissions.get("defaultMode") if isinstance(permissions, dict) else None
        if not mode:
            continue
        if mode not in PROMPTING_MODES:
            return Finding(
                "warn",
                "mode",
                f"{path} sets defaultMode {mode!r}: in that mode the plugin turns "
                f"every approval into a refusal, because no one would see the "
                f"prompt. Use default or plan for sessions that need approvals",
            )
        break
    return Finding(
        "ok",
        "mode",
        "approvals reach you in default or plan mode; in other modes, such as "
        "auto, they are refused (shift+tab to switch)",
    )


def _size(n: int) -> str:
    return f"{n / (1 << 30):.1f} GB" if n >= 1 << 30 else f"{n / (1 << 20):.0f} MB"


def check_disk(home: Path, usage: Callable[[Path], Any] = shutil.disk_usage) -> Finding:
    """Room for the ledger. A failed write fails closed: every call is refused."""
    target = home if home.exists() else home.parent
    try:
        free = usage(target).free
    except OSError as exc:
        return Finding("skip", "disk", f"cannot read free space at {target}: {exc}")
    if free < DISK_FAIL:
        return Finding(
            "FAIL",
            "disk",
            f"only {_size(free)} free where the ledger lives; when a write fails, "
            f"every decision fails closed",
        )
    if free < DISK_WARN:
        return Finding(
            "warn", "disk", f"only {_size(free)} free where the ledger lives"
        )
    return Finding("ok", "disk", f"{_size(free)} free")


def run_checks(
    url: str,
    home: Path,
    *,
    plugins_root: Path,
    settings_files: list[Path],
    fetch: Fetch = get_json,
    lan: Callable[[], str | None] = lan_address,
    connect: Callable[[str, int], bool] = can_connect,
    checkout_hook: Path | None = CHECKOUT_HOOK,
) -> list[Finding]:
    keys, pinned = check_keys(home)
    server, manifest = check_server(url, fetch)
    findings = [keys, server]
    if server.status == "ok":
        findings.append(check_signing(url, manifest, pinned))
        findings.append(check_exposure(url, lan, connect))
    else:
        findings.append(Finding("skip", "signing", "no server to ask"))
        findings.append(Finding("skip", "exposure", "no server to test"))
    findings += [
        check_plugin(plugins_root, checkout_hook),
        check_mode(settings_files),
        check_disk(home),
    ]
    return findings


def render(url: str, home: Path, findings: list[Finding]) -> str:
    lines = [f"PrivateVault doctor  (server {url}, state folder {home})", ""]
    for f in findings:
        lines.append(f"  {f.status:<5} {f.name:<9} {f.detail}")
    failed = [f.name for f in findings if f.status == "FAIL"]
    lines += [
        "",
        f"{len(failed)} problem(s): {', '.join(failed)}" if failed else "All clear.",
    ]
    return "\n".join(lines)


def cmd_doctor(args: argparse.Namespace) -> int:
    url = (args.url or os.environ.get("PV_ENFORCE_URL") or DEFAULT_URL).rstrip("/")
    home = args.home.expanduser()
    claude = Path.home() / ".claude"
    findings = run_checks(
        url,
        home,
        plugins_root=claude / "plugins",
        settings_files=[
            Path.cwd() / ".claude" / "settings.local.json",
            Path.cwd() / ".claude" / "settings.json",
            claude / "settings.json",
        ],
    )
    print(render(url, home, findings))
    return 1 if any(f.status == "FAIL" for f in findings) else 0


def add_parser(sub: argparse._SubParsersAction) -> None:
    doctor = sub.add_parser(
        "doctor",
        help="check that Claude Code, the plugin and PrivateVault agree",
        description=__doc__.split("\n\n")[0] if __doc__ else None,
    )
    doctor.add_argument(
        "--url",
        default=None,
        help=f"PrivateVault the plugin talks to (default: PV_ENFORCE_URL or {DEFAULT_URL})",
    )
    doctor.add_argument(
        "--home",
        type=Path,
        default=Path(os.environ.get("PV_HOME") or Path.home() / ".privatevault"),
        help="state folder (default: PV_HOME or ~/.privatevault)",
    )
    doctor.set_defaults(func=cmd_doctor)
