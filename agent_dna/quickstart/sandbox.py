"""Claude Code's OS sandbox, configured for PrivateVault (ADR 0034).

The plugin's hook judges a shell command by its text, which is an early
warning: a spelling the guard misreads gets through. Claude Code can also
run every Bash command in an operating-system sandbox (Seatbelt on macOS,
bubblewrap on Linux) that denies reading or writing named paths in the
kernel, however the command is spelled.

``pv up`` writes ``~/.privatevault/claude-settings.json`` and ``pv claude``
starts Claude Code with it (``claude --settings <file>``). The settings:

- run every Bash command in the sandbox, refuse to run if the sandbox is not
  available (``failIfUnavailable``), and give the model no way to ask for an
  unsandboxed command (``allowUnsandboxedCommands: false``);
- deny reading PrivateVault's state folder and the usual credential places
  (``.env`` files anywhere in the project, ``~/.ssh``, ``~/.aws``,
  ``~/.gnupg``, ``~/.kube``, ``~/.docker``, ``~/.netrc``,
  ``~/.git-credentials``), and deny writing the state folder.

``pv claude`` rewrites the file for the folder it is started in, so start it
from the project.

A settings file given with ``--settings`` is one the project's own settings
cannot weaken. The sandbox covers Bash and what it starts; Read, Write and
Edit stay with the plugin's hook and Claude Code's permission rules.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sys
import tempfile
from pathlib import Path

from agent_dna.quickstart import QuickstartError

SETTINGS_NAME = "claude-settings.json"
# Relative globs are resolved from the settings file's folder, not the
# project (found 2026-10-24: "**/.env" left the project's .env readable), so
# project patterns are written absolute, for the project Claude Code opens.
PROJECT_PATTERNS = ("**/.env", "**/.env.*")
PROTECTED_PLACES = (
    "~/.ssh",
    "~/.aws",
    "~/.gnupg",
    "~/.kube",
    "~/.docker",
    "~/.netrc",
    "~/.git-credentials",
)


def claude_settings(home: Path, project: Path) -> dict:
    """Claude Code settings that sandbox Bash away from PrivateVault's state
    and from credentials, for ``project`` (an absolute folder)."""
    state = [str(home), "~/.privatevault"]
    project_rules = [f"{project.resolve()}/{pattern}" for pattern in PROJECT_PATTERNS]
    return {
        "sandbox": {
            "enabled": True,
            "failIfUnavailable": True,
            "allowUnsandboxedCommands": False,
            "filesystem": {
                "denyRead": [*dict.fromkeys(state), *project_rules, *PROTECTED_PLACES],
                "denyWrite": list(dict.fromkeys(state)),
            },
        }
    }


def write_settings(home: Path, project: Path) -> Path:
    """Write (or refresh) the settings file for ``project``, owner-only,
    atomically."""
    path = home / SETTINGS_NAME
    fd, tmp = tempfile.mkstemp(dir=home, prefix=".tmp-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(claude_settings(home, project), fh, indent=2)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return path


def missing_requirements() -> list[str]:
    """What this machine lacks for the sandbox (Linux needs bubblewrap and
    socat; macOS has Seatbelt built in)."""
    if platform.system() != "Linux":
        return []
    return [tool for tool in ("bwrap", "socat") if shutil.which(tool) is None]


def add_parser(sub: argparse._SubParsersAction) -> None:
    run = sub.add_parser(
        "claude",
        help="start Claude Code with PrivateVault's OS sandbox settings",
        description="Start Claude Code with Bash in the OS sandbox: "
        "claude --settings ~/.privatevault/claude-settings.json [args]",
    )
    run.add_argument(
        "--home",
        type=Path,
        default=Path.home() / ".privatevault",
        help="state folder (default ~/.privatevault)",
    )
    run.add_argument("args", nargs=argparse.REMAINDER, help="passed to claude")
    run.set_defaults(func=cmd_claude)


def cmd_claude(args: argparse.Namespace) -> int:
    from agent_dna.quickstart import prepare_home

    try:
        home = args.home.expanduser().resolve()
        prepare_home(home)
        settings = write_settings(home, Path.cwd())
        missing = missing_requirements()
        if missing:
            raise QuickstartError(
                f"the sandbox needs {' and '.join(missing)} on Linux; install "
                "them (e.g. sudo apt install bubblewrap socat) and run again"
            )
        claude = shutil.which("claude")
        if claude is None:
            raise QuickstartError("claude (Claude Code) is not on PATH")
    except QuickstartError as exc:
        print(f"pv claude: {exc}", file=sys.stderr)
        return 2
    passed = list(args.args)
    if passed[:1] == ["--"]:
        passed = passed[1:]
    os.execv(claude, [claude, "--settings", str(settings), *passed])
    return 0  # not reached
