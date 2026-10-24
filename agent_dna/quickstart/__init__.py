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
import stat
import sys
from importlib import resources
from pathlib import Path

STARTER_FILES = ("policy.json", "grants.json")
BASELINE_CAPABILITIES = "shell.exec,fs.read,fs.write,net.fetch"
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
    check_private(home, directory=True)
    paths: dict[str, Path] = {}
    starter = resources.files(__package__)
    for name in STARTER_FILES:
        target = home / name
        if not os.path.lexists(target):
            with resources.as_file(starter / name) as source:
                shutil.copyfile(source, target)
            target.chmod(0o600)
        check_private(target, directory=False)
        paths[name] = target
    ensure_signing_key(home)
    return paths


def check_private(path: Path, *, directory: bool) -> None:
    """The state folder and the policy and grants it holds must be the
    user's own: not a symbolic or hard link, not someone else's, not
    writable by others. A policy file an attacker can swap or edit would
    switch every rule off (red team 2026-10-23, F1)."""
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise QuickstartError(f"cannot check {path}: {exc.strerror}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise QuickstartError(
            f"{path} is a symbolic link; PrivateVault reads its state only from "
            "files and folders it owns. Replace it with a regular file."
        )
    if directory and not stat.S_ISDIR(st.st_mode):
        raise QuickstartError(f"{path} is not a folder")
    if not directory and not stat.S_ISREG(st.st_mode):
        raise QuickstartError(f"{path} is not a regular file")
    if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
        raise QuickstartError(f"{path} belongs to another user")
    if st.st_mode & 0o022:
        raise QuickstartError(
            f"{path} is writable by other users; run: chmod go-w {path}"
        )
    if not directory and st.st_nlink > 1:
        raise QuickstartError(
            f"{path} has other hard links; replace it with a file of its own"
        )


def starter_is_current(home: Path) -> bool:
    """Does the user's policy match the starter this version ships?"""
    try:
        mine = (home / "policy.json").read_bytes()
    except OSError:
        return False
    return mine == resources.files(__package__).joinpath("policy.json").read_bytes()


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
            # Destructive programs are blocked by the guard itself, whatever
            # the policy file says (red team 2026-10-23, F1).
            "PV_SHELL_BLOCK_DESTRUCTIVE": "1",
        }
    )
    signing = read_signing_key(home)
    if signing is not None:
        # ADR 0035: every decision is signed; the plugin pins the public key.
        base["PV_RECEIPT_SIGNING_KEY"], base["PV_TRUSTED_PUBLIC_KEYS"] = signing
    return base, dropped


SIGNING_KEY_FILE = "signing.key"
PUBLIC_KEY_FILE = "decision-key.pub"
SECRET_SETTINGS = frozenset({"PV_RECEIPT_SIGNING_KEY"})


def ensure_signing_key(home: Path) -> str:
    """Create the decision-signing key on first run (owner-only) and the
    public key file the plugin pins. Returns the public key."""
    seed_path, pub_path = home / SIGNING_KEY_FILE, home / PUBLIC_KEY_FILE
    if not os.path.lexists(seed_path):
        from agent_dna.signer import generate_keypair

        pair = generate_keypair()
        fd = os.open(seed_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as fh:
            fh.write(pair["signing_key"] + "\n")
    check_private(seed_path, directory=False)
    signing = read_signing_key(home)
    if signing is None:
        raise QuickstartError(f"{seed_path} does not hold a 64-hex Ed25519 seed")
    public = signing[1]
    if not os.path.lexists(pub_path) or pub_path.read_text().strip() != public:
        pub_path.write_text(public + "\n")
        pub_path.chmod(0o644)
    check_private(pub_path, directory=False)
    return public


def read_signing_key(home: Path) -> tuple[str, str] | None:
    """(seed, public key) from the state folder, or None if there is none."""
    try:
        seed = (home / SIGNING_KEY_FILE).read_text(encoding="ascii").strip()
    except (OSError, ValueError):
        return None
    try:
        from nacl.signing import SigningKey

        public = SigningKey(bytes.fromhex(seed)).verify_key.encode().hex()
    except (ValueError, TypeError):
        return None
    return seed, public


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
        f"  signing    every decision; the plugin checks it with {home / PUBLIC_KEY_FILE}",
    ]
    if dropped:
        lines.append(f"  ignored    {', '.join(dropped)} (pv up sets its own)")
    if not starter_is_current(home):
        lines.append(
            "  note       your policy.json differs from this version's starter; "
            "to take the new starter, move yours aside and restart"
        )
    from agent_dna.quickstart.sandbox import SETTINGS_NAME, missing_requirements

    lines += [
        "",
        "In Claude Code, once:",
        "  /plugin marketplace add LOLA0786/privatevault-agent-dna",
        "  /plugin install privatevault@privatevault",
        "",
        "Start Claude Code with Bash in the OS sandbox (recommended):",
        f"  pv claude          (= claude --settings {home / SETTINGS_NAME})",
    ]
    missing = missing_requirements()
    if missing:
        lines.append(
            f"  needs {' and '.join(missing)} on Linux: sudo apt install bubblewrap socat"
        )
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
        from agent_dna.quickstart.sandbox import write_settings

        write_settings(home, workdir)
        env, dropped = server_environment(home, workdir)
        if args.print_env:
            for name in sorted(k for k in env if k.startswith("PV_")):
                shown = (
                    f"<{home / SIGNING_KEY_FILE}>"
                    if name in SECRET_SETTINGS
                    else env[name]
                )
                print(f"{name}={shown}")
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
