"""``pv up``: a local PrivateVault for one developer, in one command.

    uvx --from git+https://github.com/LOLA0786/privatevault-agent-dna pv up

starts the decision API on 127.0.0.1:8000 with the starter policy and grants
the Claude Code plugin is written against (``integrations/claude-code``).
State lives in ``~/.privatevault``:

    ledger.db      sealed, hash-chained decisions
    policy.json    rules (copied from the starter on first run, then yours)
    grants.json    what the agent may do at all (likewise)

Files you have edited are never overwritten. The server runs WITHOUT
authentication (``PV_ALLOW_NO_AUTH=1``), so it binds to loopback only and
refuses any other address; a team deployment uses API keys or the secure
profile instead (see the README).

Inherited ``PV_*`` settings are ignored, so ``pv up`` behaves the same on
every machine; the ones dropped are named on start.
"""

from __future__ import annotations

import argparse
import errno
import ipaddress
import json
import os
import re
import shutil
import socket
import sys
from importlib import resources
from pathlib import Path

STARTER_FILES = ("policy.json", "grants.json")
BASELINE_CAPABILITIES = "shell.exec,fs.write,net.fetch"
AGENT_ID = "claude-code"
# Same shape composition.parse_baseline_capabilities accepts.
_BASELINE_CAPABILITY_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,127}")
LOOPBACK_NAMES = {"localhost"}


class QuickstartError(RuntimeError):
    """``pv up`` cannot start; the message says why and what to do."""


def is_loopback(host: str) -> bool:
    if host.lower() in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def prepare_home(home: Path) -> dict[str, Path]:
    """Create the state folder (owner-only) and the starter files missing from it.
    Returns the path of each starter file."""
    home.mkdir(parents=True, exist_ok=True)
    try:
        home.chmod(0o700)
    except OSError:
        pass  # a folder the user owns but cannot chmod (some mounts): keep going
    paths: dict[str, Path] = {}
    starter = resources.files(__package__)
    for name in STARTER_FILES:
        target = home / name
        if not target.exists():
            with resources.as_file(starter / name) as source:
                shutil.copyfile(source, target)
        paths[name] = target
    return paths


def baseline_capabilities(grants_file: Path) -> str:
    """The drift baseline: the plugin's three capabilities plus every
    capability granted to the agent. Writing a grant is the operator saying
    "this is normal"; without it, drift review would hold every granted MCP
    tool for approval, which the gateway (``pv wrap``) can only refuse.
    Unreadable grants leave the base list: the server then refuses the
    file itself."""
    caps = set(BASELINE_CAPABILITIES.split(","))
    try:
        grants = json.loads(grants_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        grants = []
    for grant in grants if isinstance(grants, list) else []:
        if not isinstance(grant, dict) or grant.get("agent_id") != AGENT_ID:
            continue
        cap = grant.get("capability")
        if isinstance(cap, str) and _BASELINE_CAPABILITY_RE.fullmatch(cap):
            caps.add(cap)
    return ",".join(sorted(caps))


def server_environment(
    home: Path, workdir: Path, environ: dict[str, str] | None = None
) -> tuple[dict[str, str], list[str]]:
    """The environment the API starts with, and the inherited PV_* names dropped."""
    base = dict(os.environ if environ is None else environ)
    dropped = sorted(name for name in base if name.startswith("PV_"))
    for name in dropped:
        del base[name]
    base.update(
        {
            "PV_ALLOW_NO_AUTH": "1",
            "PV_DB_PATH": str(home / "ledger.db"),
            "PV_POLICY_FILE": str(home / "policy.json"),
            "PV_GRANTS_FILE": str(home / "grants.json"),
            "PV_BASELINE_CAPABILITIES": baseline_capabilities(home / "grants.json"),
            "PV_SHELL_WORKDIR": str(workdir),
        }
    )
    return base, dropped


def check_port_free(host: str, port: int) -> None:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as probe:
        try:
            probe.bind((host, port))
        except OSError as exc:
            if exc.errno == errno.EADDRINUSE:
                raise QuickstartError(
                    f"port {port} on {host} is in use. If PrivateVault is already "
                    f"running, check it with: curl -s http://{host}:{port}/health\n"
                    f"Otherwise pick another port (pv up --port 8001) and start "
                    f"Claude Code with PV_ENFORCE_URL=http://{host}:8001"
                ) from exc
            raise QuickstartError(f"cannot listen on {host}:{port}: {exc}") from exc


def _banner(host: str, port: int, home: Path, workdir: Path, dropped: list[str]) -> str:
    url = f"http://{host}:{port}"
    lines = [
        f"PrivateVault is starting on {url} (no authentication: this machine only)",
        f"  ledger     {home / 'ledger.db'}",
        f"  policy     {home / 'policy.json'}",
        f"  grants     {home / 'grants.json'}",
        f"  project    {workdir}   (the shell guard may read files here)",
    ]
    if dropped:
        lines.append(f"  ignored    {', '.join(dropped)} (pv up sets its own)")
    lines += [
        "",
        "In Claude Code, once:",
        "  /plugin marketplace add LOLA0786/privatevault-agent-dna",
        "  /plugin install privatevault@privatevault",
    ]
    if port != 8000 or host not in ("127.0.0.1", "localhost"):
        lines.append(f"and start Claude Code with PV_ENFORCE_URL={url}")
    lines += [
        "",
        f"Review decisions:  curl -s {url}/v1/records/claude-code",
        f"Verify the chain:  curl -s {url}/v1/verify",
        "Stop: Ctrl-C",
        "",
    ]
    return "\n".join(lines)


def add_parser(sub: argparse._SubParsersAction) -> None:
    up = sub.add_parser(
        "up",
        help="run a local PrivateVault for the Claude Code plugin",
        description=__doc__.split("\n\n")[0] if __doc__ else None,
    )
    up.add_argument("--port", type=int, default=8000)
    up.add_argument(
        "--host",
        default="127.0.0.1",
        help="loopback address to listen on (default 127.0.0.1)",
    )
    up.add_argument(
        "--home",
        type=Path,
        default=Path.home() / ".privatevault",
        help="state folder (default ~/.privatevault)",
    )
    up.add_argument(
        "--workdir",
        type=Path,
        default=Path.cwd(),
        help="project folder the shell guard may read (default: current folder)",
    )
    up.add_argument(
        "--print-env",
        action="store_true",
        help="prepare the state folder, print the server settings and exit",
    )
    up.set_defaults(func=cmd_up)


def cmd_up(args: argparse.Namespace) -> int:
    try:
        if not is_loopback(args.host):
            raise QuickstartError(
                f"{args.host} is not a loopback address. pv up runs without "
                "authentication and listens only on this machine; for a shared "
                "server use API keys (PV_API_KEYS_FILE) or PV_SECURE_PROFILE=1."
            )
        if not 1 <= args.port <= 65535:
            raise QuickstartError(f"--port {args.port} is not a TCP port")
        workdir = args.workdir.expanduser().resolve()
        if not workdir.is_dir():
            raise QuickstartError(f"--workdir {workdir} is not a folder")
        home = args.home.expanduser().resolve()
        prepare_home(home)
        env, dropped = server_environment(home, workdir)
        if args.print_env:
            for name in sorted(k for k in env if k.startswith("PV_")):
                print(f"{name}={env[name]}")
            return 0
        check_port_free(args.host, args.port)
    except QuickstartError as exc:
        print(f"pv up: {exc}", file=sys.stderr)
        return 2

    print(_banner(args.host, args.port, home, workdir, dropped), flush=True)
    for name in dropped:
        os.environ.pop(name, None)
    os.environ.update(env)
    import uvicorn

    uvicorn.run("api.server:app", host=args.host, port=args.port, log_level="info")
    return 0
