"""``pv wrap``: run an MCP server behind the PrivateVault gateway.

    pv secret set stripe STRIPE_SECRET_KEY          # once; prompts, stores 0600
    claude mcp add stripe -- uvx --from git+https://github.com/LOLA0786/privatevault-agent-dna \\
        pv wrap --name stripe -- npx -y @stripe/mcp

Claude Code starts ``pv wrap`` as the MCP server. ``pv wrap`` starts the real
server as its child and sits between them (``agent_dna.gateway``):

- The server's credentials are read from ``~/.privatevault/mcp-secrets/<name>.env``
  and handed only to the child's environment. They are not in Claude Code's
  configuration; a credential value in anything the server sends back is
  redacted before Claude sees it, and the gateway stops rather than send
  one to the server inside a request.
- Every ``tools/call``, resource read and prompt is decided before a byte
  reaches the server, as ``mcp.<name>.<tool>``: the same capability name the
  plugin's hook uses, against the same ``policy.json`` and ``grants.json`` as
  ``pv up``. Only allow is forwarded; block is refused, and require-approval
  is refused until a person runs ``pv approve <id>`` for that exact call
  (ADR 0036, ``agent_dna/quickstart/approvals.py``).
- Tools the server did not declare are refused; unknown methods fail closed.
- Decisions are sealed in ``~/.privatevault/mcp/<name>.db``, one hash chain
  per server (one process writes each ledger).

The child gets only a short list of ordinary variables (PATH, HOME, locale,
temp folders), the ones named with ``--pass-env`` (a proxy, a CA bundle) and
its credentials: not your shell's other secrets.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

from agent_dna.gateway.credentials import UpstreamCredentials
from agent_dna.quickstart import (
    AGENT_ID,
    QuickstartError,
    prepare_home,
    server_environment,
)

NAME_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,39}")
VAR_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
SECRETS_DIR = "mcp-secrets"
LEDGER_DIR = "mcp"
MAX_SECRET_FILE_BYTES = 64 * 1024
PROXY_VARS = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")


def _check_name(name: str) -> str:
    if not NAME_RE.fullmatch(name):
        raise QuickstartError(
            f"server name {name!r}: 1-40 of a-z, 0-9, '_' and '-', starting with a "
            "letter or digit (it becomes the mcp.<name>. capability prefix)"
        )
    return name


def _private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def secret_file(home: Path, name: str) -> Path:
    return home / SECRETS_DIR / f"{_check_name(name)}.env"


def _owner_only_text(path: Path) -> str | None:
    """The file's text, if only its owner can read it. Missing: None."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise QuickstartError(f"cannot open {path}: {exc.strerror}") from exc
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise QuickstartError(f"{path} is not a regular file")
        if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
            raise QuickstartError(f"{path} belongs to another user")
        if st.st_nlink > 1:
            raise QuickstartError(
                f"{path} has other hard links; replace it with a file of its own"
            )
        if st.st_mode & 0o077:
            raise QuickstartError(
                f"{path} is readable by others; run: chmod 600 {path}"
            )
        data = fh.read(MAX_SECRET_FILE_BYTES + 1)
    if len(data) > MAX_SECRET_FILE_BYTES:
        raise QuickstartError(f"{path} is larger than 64 KiB")
    return data.decode("utf-8")


def _assignments(path: Path, text: str) -> list[tuple[str, str]]:
    """NAME=value lines, in order; blank lines and # comments skipped."""
    out: list[tuple[str, str]] = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        var, sep, rest = line.partition("=")
        var = var.strip()
        if not sep or not VAR_RE.fullmatch(var):
            raise QuickstartError(f"{path}:{number}: expected NAME=value")
        out.append((var, rest.strip()))
    return out


def read_secrets(path: Path) -> dict[str, str]:
    """KEY=VALUE lines from a file only its owner can read. Missing: none."""
    text = _owner_only_text(path)
    return {} if text is None else dict(_assignments(path, text))


def stored_names(path: Path) -> list[str]:
    """The names in a secret file, never the values (``pv secret list``)."""
    text = _owner_only_text(path)
    if text is None:
        return []
    return sorted({var for var, _ in _assignments(path, text)})


def write_secret(home: Path, name: str, var: str, value: str) -> None:
    """Set one NAME=value in the server's secret file (0600, atomic)."""
    if not VAR_RE.fullmatch(var):
        raise QuickstartError(f"{var!r} is not an environment variable name")
    if not value or "\n" in value or "\r" in value:
        raise QuickstartError("the value must be one non-empty line")
    path = secret_file(home, name)
    _private_dir(path.parent)
    secrets = read_secrets(path)
    secrets[var] = value
    body = "".join(f"{k}={v}\n" for k, v in sorted(secrets.items()))
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _agent_key_file(home: Path, name: str) -> tuple[str, Path]:
    """A fresh agent key for this run; only its hash is written down."""
    from agent_dna.apikeys import generate_key

    entry = generate_key(AGENT_ID)
    path = _private_dir(home / LEDGER_DIR) / f"{name}.keys.json"
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({entry["hash"]: AGENT_ID}, fh)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return entry["key"], path


def _credentials(secrets: dict[str, str], pass_env: list[str]) -> UpstreamCredentials:
    names = set()
    for var in pass_env:
        if not VAR_RE.fullmatch(var) or var.upper().startswith("PV_"):
            raise QuickstartError(f"--pass-env {var!r} is not a variable you can pass")
        names.add(var)
    try:
        return UpstreamCredentials(env=secrets, passthrough=frozenset(names))
    except ValueError as exc:
        raise QuickstartError(
            f"--pass-env: {exc}; store secrets with: pv secret set"
        ) from exc


def gateway_environment(
    home: Path, name: str, keys_file: Path, environ: dict[str, str] | None = None
) -> dict[str, str]:
    """``pv up``'s settings, with API-key identity instead of no-auth and a
    ledger of this server's own."""
    env, _dropped = server_environment(home, Path.cwd(), environ)
    del env["PV_ALLOW_NO_AUTH"]
    env["PV_API_KEYS_FILE"] = str(keys_file)
    env["PV_DB_PATH"] = str(home / LEDGER_DIR / f"{name}.db")
    from agent_dna.quickstart.approvals import bundle_path

    bundle = bundle_path(home)
    if bundle is not None:  # ADR 0036: pv approve can satisfy require_approval
        env["PV_APPROVER_TRUST_BUNDLE"] = str(bundle)
    return env


def add_parsers(sub: argparse._SubParsersAction) -> None:
    wrap = sub.add_parser(
        "wrap",
        help="run an MCP server behind the PrivateVault gateway (stdio)",
        description="Run an MCP server behind the PrivateVault gateway.",
    )
    wrap.add_argument("--name", required=True, help="server name, e.g. stripe")
    wrap.add_argument(
        "--home",
        type=Path,
        default=Path.home() / ".privatevault",
        help="state folder (default ~/.privatevault)",
    )
    wrap.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="seconds to wait for each server answer (default 60)",
    )
    wrap.add_argument(
        "--pass-env",
        action="append",
        default=[],
        metavar="NAME",
        help="also give the server this variable from your environment, e.g. "
        "HTTPS_PROXY or NODE_EXTRA_CA_CERTS (not for secrets: use pv secret set)",
    )
    wrap.add_argument("command", nargs=argparse.REMAINDER, help="-- server command")
    wrap.set_defaults(func=cmd_wrap)

    secret = sub.add_parser("secret", help="credentials for wrapped MCP servers")
    ssub = secret.add_subparsers(dest="secret_action", required=True)
    put = ssub.add_parser("set", help="store NAME for a server (prompts for it)")
    put.add_argument("server")
    put.add_argument("var", metavar="NAME")
    put.add_argument("--home", type=Path, default=Path.home() / ".privatevault")
    put.set_defaults(func=cmd_secret_set)
    names = ssub.add_parser("list", help="names stored for a server (never values)")
    names.add_argument("server")
    names.add_argument("--home", type=Path, default=Path.home() / ".privatevault")
    names.set_defaults(func=cmd_secret_list)


def cmd_secret_set(args: argparse.Namespace) -> int:
    try:
        home = args.home.expanduser().resolve()
        if sys.stdin.isatty():
            value = getpass.getpass(f"{args.var} for {args.server}: ")
        else:
            value = sys.stdin.readline().rstrip("\r\n")
        write_secret(home, args.server, args.var, value)
        where = secret_file(home, args.server)
    except QuickstartError as exc:
        print(f"pv secret: {exc}", file=sys.stderr)
        return 2
    print(f"stored {args.var} in {where} (owner-only)")
    return 0


def cmd_secret_list(args: argparse.Namespace) -> int:
    try:
        path = secret_file(args.home.expanduser().resolve(), args.server)
        for var in stored_names(path):
            print(var)
    except QuickstartError as exc:
        print(f"pv secret: {exc}", file=sys.stderr)
        return 2
    return 0


def cmd_wrap(args: argparse.Namespace) -> int:
    command = list(args.command)
    if command[:1] == ["--"]:
        command = command[1:]
    # stdout belongs to the MCP client. Keep a private handle to it and point
    # fd 1 at stderr, so nothing else (a library's print, a warning) can
    # corrupt the protocol stream.
    mcp_out = os.fdopen(os.dup(1), "wb", buffering=0)
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    try:
        if not command:
            raise QuickstartError("give the server command after --")
        if not 0 < args.timeout <= 600:
            raise QuickstartError("--timeout must be between 0 and 600 seconds")
        name = _check_name(args.name)
        home = args.home.expanduser().resolve()
        prepare_home(home)
        secrets = read_secrets(secret_file(home, name))
        agent_key, keys_file = _agent_key_file(home, name)
        env = gateway_environment(home, name, keys_file)
        credentials = _credentials(secrets, args.pass_env)
    except QuickstartError as exc:
        print(f"pv wrap: {exc}", file=sys.stderr)
        return 2

    for var in [n for n in os.environ if n.startswith("PV_")]:
        del os.environ[var]
    os.environ.update({k: v for k, v in env.items() if k.startswith("PV_")})

    from agent_dna.composition import RuntimeConfig, build_production_runtime
    from agent_dna.gateway import GatewayConfig, McpGateway
    from agent_dna.gateway.errors import FramingProtocolError, GatewayStartupError
    from agent_dna.gateway.framing import FramingMode
    from agent_dna.gateway.stdio_proxy import serve_stdio

    try:
        runtime = build_production_runtime(RuntimeConfig.from_env())
        gateway = McpGateway.from_stdio_command(
            runtime,
            config=GatewayConfig(
                agent_api_key=agent_key,
                client_identity=AGENT_ID,
                transport="stdio",
                framing_mode=FramingMode.NEWLINE,
                upstream_timeout_s=args.timeout,
                capability_prefix=f"mcp.{name}.",
            ),
            credentials=credentials,
            command=command,
        )
    except (GatewayStartupError, RuntimeError, ValueError, OSError) as exc:
        print(f"pv wrap: gateway refused to start: {exc}", file=sys.stderr)
        return 1
    from agent_dna.quickstart.approvals import ApprovingMiddleware

    configured = "PV_APPROVER_TRUST_BUNDLE" in env
    gateway.wrap_middleware(
        lambda inner: ApprovingMiddleware(inner, home, configured=configured)
    )
    unpassed = [
        v for v in PROXY_VARS if os.environ.get(v) and v not in credentials.passthrough
    ]
    if unpassed:
        print(
            f"pv wrap: note: {', '.join(unpassed)} set but not given to the server; "
            "if it needs the network through a proxy, add --pass-env for each",
            file=sys.stderr,
        )
    print(
        f"pv wrap: {name} behind PrivateVault; decisions in "
        f"{env['PV_DB_PATH']}; {len(secrets)} credential(s) for the server only",
        file=sys.stderr,
    )
    try:
        serve_stdio(gateway, client_out=mcp_out)
    except FramingProtocolError as exc:
        print(f"pv wrap: session closed: {exc}", file=sys.stderr)
        return 1
    finally:
        gateway.upstream.close()
    return 0
