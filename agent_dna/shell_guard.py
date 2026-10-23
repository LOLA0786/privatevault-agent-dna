"""Shell guard: server-derived analysis of shell commands (escalate-only).

A policy that checks only the first word of a command ("rm") is bypassed by
``sh -c "rm -rf ..."``, ``env rm``, ``xargs rm`` or ``curl --data-binary
@.env``. External testing (2026-10-15) found exactly that. Arbitrary shell
cannot be fully understood, so this module does two things:

1. **Evidence.** For capabilities configured as shell capabilities
   (``PV_SHELL_CAPABILITIES``, default ``shell.exec``) the runtime derives
   ``evidence.shell`` from the action's own arguments. Callers cannot supply
   it: whatever they send under that key is replaced. Wrappers (env, sudo,
   timeout, xargs, nice, find -exec, ...) and nested shells are unwrapped,
   so policy rules see every program that would run::

       {"field": "evidence.shell.executables", "operator": "any_in",
        "value": ["rm", "dd", "mkfs"]}                      -> block
       {"field": "evidence.shell.executables", "operator": "any_not_in",
        "value": ["ls", "cat", "git", "pytest"]}            -> allowlist

2. **Default deny** (no policy needed). The decision is escalated to BLOCK
   when the command cannot be parsed, when it carries code the runtime
   cannot see (``sh -c``, ``python -c``, ``eval``, ``$(...)``, a shell
   reading stdin), when a network tool is handed a credential-like file,
   or when such a file is copied, linked, packed, re-encoded or redirected
   to another file (staging it under an innocent name for a later step).
   ``PV_SHELL_ALLOW_INLINE=1`` lifts only the inline-code rule.

Accepted argument shapes, in order: ``argv`` (list, exec-style),
``command`` + ``args`` (exec-style), ``command`` / ``cmd`` as a string
(shell-style). Anything else is unparseable and therefore blocked.
"""

from __future__ import annotations

import contextvars
import fnmatch
import glob
import hashlib
import json
import math
import os
import re
import shlex
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, cast

from .advisory import Severity
from .decision import Decision, DecisionResult
from .evidence import EvidenceItem, EvidenceReport

SHELL_CAPABILITIES_ENV = "PV_SHELL_CAPABILITIES"
ALLOW_INLINE_ENV = "PV_SHELL_ALLOW_INLINE"
DEFAULT_SHELL_CAPABILITIES = frozenset({"shell.exec"})
TRIGGERED_BY_SHELL = "shell_guard"
SHELL_EVIDENCE_ITEM = "shell_guard"

WORKDIR_ENV = "PV_SHELL_WORKDIR"
SECRET_FILES_ENV = "PV_SHELL_SECRET_FILES"
SECRET_VARS_ENV = "PV_SHELL_SECRET_VARS"
MAX_INSPECT_BYTES = 1_048_576
MIN_SECRET_VALUE_CHARS = 8

SHELL_UNPARSEABLE = "SHELL_UNPARSEABLE"
SHELL_INLINE_CODE = "SHELL_INLINE_CODE"
SHELL_SECRET_EGRESS = "SHELL_SECRET_EGRESS"
SHELL_SCRIPT_SECRET = "SHELL_SCRIPT_SECRET"
SHELL_SECRET_STAGING = "SHELL_SECRET_STAGING"
SHELL_SCRIPT_DESTRUCTIVE = "SHELL_SCRIPT_DESTRUCTIVE"
SHELL_SCRIPT_UNINSPECTABLE = "SHELL_SCRIPT_UNINSPECTABLE"
ALLOW_DESTRUCTIVE_SCRIPTS_ENV = "PV_SHELL_ALLOW_DESTRUCTIVE_SCRIPTS"
BLOCK_DESTRUCTIVE_ENV = "PV_SHELL_BLOCK_DESTRUCTIVE"
SHELL_DESTRUCTIVE = "SHELL_DESTRUCTIVE"

MAX_DEPTH = 4
MAX_COMMAND_CHARS = 16_384

SHELLS = frozenset(
    {"sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "csh", "tcsh"}
)
# interpreter -> flags that take code on the command line
INLINE_FLAGS: dict[str, frozenset[str]] = {
    "python": frozenset({"-c"}),
    "perl": frozenset({"-e", "-E"}),
    "ruby": frozenset({"-e"}),
    "node": frozenset({"-e", "--eval", "-p", "--print"}),
    "php": frozenset({"-r"}),
    "lua": frozenset({"-e"}),
    "osascript": frozenset({"-e"}),
    "pwsh": frozenset({"-c", "-command", "-encodedcommand", "-e", "-enc"}),
    "powershell": frozenset({"-c", "-command", "-encodedcommand", "-e", "-enc"}),
}
INTERPRETERS = frozenset(INLINE_FLAGS) | frozenset({"deno", "bun", "awk", "gawk"})
EVAL_WORDS = frozenset({"eval", "source", "."})
WRAPPERS = frozenset(
    {
        "env",
        "sudo",
        "doas",
        "nohup",
        "nice",
        "ionice",
        "timeout",
        "stdbuf",
        "time",
        "command",
        "builtin",
        "exec",
        "xargs",
        "setsid",
        "chrt",
        "taskset",
        "unbuffer",
        "busybox",
    }
)
# wrapper options that consume the next token
_OPTS_WITH_ARG: dict[str, frozenset[str]] = {
    "env": frozenset({"-u", "--unset", "-C", "--chdir"}),
    "sudo": frozenset({"-u", "-g", "-C", "-h", "-p", "-U", "-r", "-t", "-D", "-R"}),
    "doas": frozenset({"-u", "-C"}),
    "nice": frozenset({"-n", "--adjustment"}),
    "ionice": frozenset({"-c", "-n", "-p", "-P", "-u"}),
    "timeout": frozenset({"-s", "--signal", "-k", "--kill-after"}),
    "xargs": frozenset({"-I", "-i", "-n", "-P", "-d", "-L", "-s", "-E", "-a"}),
    "taskset": frozenset(),
    "chrt": frozenset(),
}
# wrappers whose first positional argument is a parameter, not the command
_LEADING_PARAM = frozenset({"timeout", "chrt", "taskset"})
NETWORK = frozenset(
    {
        "curl",
        "wget",
        "nc",
        "ncat",
        "netcat",
        "socat",
        "ssh",
        "scp",
        "sftp",
        "rsync",
        "ftp",
        "tftp",
        "telnet",
        "http",
        "https",
        "aria2c",
        "lftp",
    }
)
# Programs that copy, rename, link, pack or re-encode files. Pointed at a
# credential-like file they stage it under an innocent name for a later
# step (external retest 2026-10-16: E06 symlink, E10/E11 copy-then-send).
STAGING = frozenset(
    {
        "cp",
        "mv",
        "ln",
        "link",
        "install",
        "rsync",
        "tar",
        "zip",
        "7z",
        "gzip",
        "bzip2",
        "xz",
        "zstd",
        "base64",
        "base32",
        "xxd",
        "od",
        "hexdump",
        "openssl",
        "gpg",
        "tee",
        "split",
        "dd",
    }
)
DESTRUCTIVE = frozenset(
    {
        "rm",
        "rmdir",
        "unlink",
        "shred",
        "dd",
        "wipefs",
        "fdisk",
        "sfdisk",
        "parted",
        "shutdown",
        "reboot",
        "halt",
        "poweroff",
        "truncate",
        "chmod",
        "chown",
        "chgrp",
    }
)
_CONTROL = frozenset({";", "&&", "||", "|", "&", ";;", "|&", "(", ")", "\n"})
_REDIRECT_IN = frozenset({"<", "<<<"})
_REDIRECT_OUT = frozenset({">", ">>", ">|", "&>", "&>>", ">&"})
_KEYWORDS = frozenset(
    {"if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done"}
    | {"case", "esac", "!", "{", "}", "function", "select", "in"}
)
_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_PY = re.compile(r"python[0-9.]*\Z")
_SENSITIVE = re.compile(
    r"(^|/)(\.env(\.[^/]*)?|\.netrc|\.npmrc|\.pypirc|\.git-credentials|"
    r"id_(rsa|dsa|ecdsa|ed25519)[^/]*|\.?credentials(\.[^/]*)?|[^/]*\.(pem|key|p12|pfx))$"
    r"|(^|/)\.(ssh|aws|gnupg|kube|docker)(/|$)"
    r"|^/proc/[^/]+/environ$"
    r"|secret",
    re.IGNORECASE,
)


class _UnparseableError(ValueError):
    pass


# Assigning one of these makes an ordinary command run a program of the
# caller's choosing: git's pager, editor and ssh, the shell's startup file,
# the dynamic loader, an interpreter's startup code, PATH itself (red team
# 2026-10-23, F3). The command is then inline code.
EXEC_ENV = frozenset(
    {
        "PATH",
        "PAGER",
        "MANPAGER",
        "EDITOR",
        "VISUAL",
        "GIT_PAGER",
        "GIT_EDITOR",
        "GIT_SEQUENCE_EDITOR",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_EXTERNAL_DIFF",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "GIT_PROXY_COMMAND",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_EXEC_PATH",
        "GIT_TEMPLATE_DIR",
        "GIT_DIR",
        "LESSOPEN",
        "LESSCLOSE",
        "BASH_ENV",
        "ENV",
        "PROMPT_COMMAND",
        "PYTHONSTARTUP",
        "PYTHONPATH",
        "PYTHONHOME",
        "PERL5OPT",
        "PERL5LIB",
        "RUBYOPT",
        "RUBYLIB",
        "NODE_OPTIONS",
        "NODE_PATH",
    }
)
EXEC_ENV_PREFIXES = ("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_", "LD_", "DYLD_")

# git configuration a command line may set without being able to run code.
# Any other key (core.pager, diff.external, alias.*, credential.helper,
# filter.*, include.path, ...) can, so it marks the command inline code.
_GIT_SAFE_KEYS = (
    "user.",
    "color.",
    "advice.",
    "init.defaultbranch",
    "safe.directory",
    "commit.gpgsign",
    "tag.gpgsign",
    "core.quotepath",
    "core.autocrlf",
    "core.safecrlf",
    "core.filemode",
    "core.longpaths",
    "core.abbrev",
    "log.date",
    "log.decorate",
    "pull.rebase",
    "pull.ff",
    "push.default",
    "push.autosetupremote",
    "fetch.prune",
    "rebase.autostash",
    "merge.conflictstyle",
    "diff.renames",
    "diff.algorithm",
    "status.",
    "column.",
    "i18n.",
    "gc.auto",
    "maintenance.auto",
    "protocol.version",
)
# git global options that take the next token as their value
_GIT_OPTS_WITH_ARG = frozenset(
    {"-C", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--list-cmds"}
)
# uv run options that take the next token as their value
_UV_RUN_OPTS_WITH_ARG = frozenset(
    {
        "--with",
        "--with-editable",
        "--with-requirements",
        "--python",
        "-p",
        "--directory",
        "--project",
        "--package",
        "--extra",
        "--group",
        "--only-group",
        "--no-group",
        "--env-file",
        "--index",
        "--default-index",
        "--index-url",
        "-i",
        "--extra-index-url",
        "--find-links",
        "-f",
        "--index-strategy",
        "--keyring-provider",
        "--resolution",
        "--prerelease",
        "--fork-strategy",
        "--exclude-newer",
        "--config-setting",
        "-C",
        "--link-mode",
        "--refresh-package",
        "--upgrade-package",
        "-P",
        "--reinstall-package",
        "--no-build-package",
        "--no-binary-package",
        "--cache-dir",
        "--config-file",
        "--color",
        "--allow-insecure-host",
        "--python-preference",
    }
)
# uv subcommands that install packages, which runs their build code
_UV_INSTALLS = frozenset({"add", "sync", "pip", "build", "tool"})

# Credential-like names a glob may stand for (red team 2026-10-23, F5): a
# pattern such as ".e*" or "~/.ss*/id_*" is judged by what it could match.
_SENSITIVE_NAMES = (
    ".env",
    ".env.local",
    ".env.production",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    ".credentials",
    "credentials",
    "credentials.json",
    "secrets",
    "secret",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "server.key",
    "key.pem",
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".docker",
    "environ",
)
_GLOB_CHARS = re.compile(r"[*?\[]")
_BRACES = re.compile(r"\{([^{}]*,[^{}]*)\}")
_VAR_USE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
MAX_GLOB_HITS = 256


@dataclass
class _Acc:
    executables: list[str] = field(default_factory=list)
    inline_code: bool = False
    interpreter: bool = False
    operators: bool = False
    reads_files: list[str] = field(default_factory=list)
    writes_files: list[str] = field(default_factory=list)
    sensitive_args: list[str] = field(default_factory=list)
    destructive_flags: bool = False
    script_secret: list[str] = field(default_factory=list)
    script_destructive: list[str] = field(default_factory=list)
    script_uninspectable: list[str] = field(default_factory=list)
    script_executables: list[str] = field(default_factory=list)
    # (token, real path, sha256, size) of every file whose bytes the guard
    # inspected. Sealed into the decision record so an executor can refuse
    # to run if the file changed after the decision (time of check vs use).
    pinned: dict[str, dict[str, Any]] = field(default_factory=dict)
    # NAME=value assignments seen so far in this command, so "F=.env; cat $F"
    # is judged as "cat .env" (red team 2026-10-23, F5).
    assigned: dict[str, str] = field(default_factory=dict)

    def note_exe(self, name: str) -> None:
        if name not in self.executables:
            self.executables.append(name)


def shell_capabilities() -> frozenset[str]:
    raw = os.environ.get(SHELL_CAPABILITIES_ENV)
    if raw is None:
        return DEFAULT_SHELL_CAPABILITIES
    return frozenset(c.strip() for c in raw.split(",") if c.strip())


def _canon(word: str) -> str:
    name = os.path.basename(word).lower()
    if _PY.match(name):
        return "python"
    if name.endswith(".exe"):
        name = name[:-4]
    return name


# A secret passed by environment variable ("$API_TOKEN") is as sensitive as
# a .env file (external retest 2026-10-16, N12).
_SECRET_VAR = re.compile(
    r"\$\{?[A-Za-z0-9_]*(TOKEN|SECRET|PASSW|API_?KEY|PRIVATE_?KEY|CREDENTIAL|"
    r"ACCESS_?KEY|AUTH)[A-Za-z0-9_]*\}?",
    re.IGNORECASE,
)


# ---- filesystem- and value-aware checks (external retest 3, 2026-10-16) ----
# Name patterns miss an existing symlink to .env (E06/X09), a copy made
# outside the guard (X01), a curl config file (X12), a script that reads a
# secret (N17), and a secret held in an innocently named variable (X03).
# These checks need the guard to see the agent's filesystem: they run only
# when the operator sets PV_SHELL_WORKDIR (the agent's working directory on
# this host). Callers cannot choose it.


def _workdir() -> str | None:
    wd = os.environ.get(WORKDIR_ENV)
    return wd if wd and os.path.isdir(wd) else None


def _resolve(token: str) -> str | None:
    """Real path of an existing file named by token, or None."""
    wd = _workdir()
    if wd is None or not token or "://" in token or len(token) > 4096:
        return None
    path = token if os.path.isabs(token) else os.path.join(wd, token)
    try:
        if os.path.lexists(path):
            real = os.path.realpath(path)
            pins = _PINS.get()
            if pins is not None:
                pins["tokens"].setdefault(real, []).append(token)
            return real
    except (OSError, ValueError):
        return None
    return None


# Collector for the files inspected during one analysis (set by
# analyze_shell_arguments). Each read is pinned by SHA-256 of the whole file.
_PINS: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "pv_shell_pins", default=None
)
MAX_PIN_BYTES = 64 * 1_048_576
# Per analysis: one request cannot make the API open or hash without bound.
MAX_FILES_PER_ANALYSIS = 64
MAX_HASH_BYTES_PER_ANALYSIS = 128 * 1_048_576


def _within_workdir(real: str) -> bool:
    """Confinement (review 2026-10-20): the guard reads, pins and reports
    only files inside PV_SHELL_WORKDIR. Reading elsewhere would turn the
    sealed evidence (path, SHA-256, size) returned to the agent into a probe
    of every file the API process can read."""
    wd = _workdir()
    if wd is None:
        return False
    root = os.path.realpath(wd)
    return real == root or real.startswith(root.rstrip(os.sep) + os.sep)


def _open_regular(path: str) -> int | None:
    """An fd on a regular file, never following a final symlink and never
    blocking on a FIFO or device swapped in after a check."""
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            return None
    except OSError:
        os.close(fd)
        return None
    return fd


def _read_operator_file(path: str) -> bytes | None:
    """A file the operator configured (PV_SHELL_SECRET_FILES): read on the
    operator's behalf, never confined, never pinned or reported."""
    fd = _open_regular(path)
    if fd is None:
        return None
    with os.fdopen(fd, "rb") as fh:
        return fh.read(MAX_INSPECT_BYTES)


def _read_limited(path: str) -> bytes | None:
    """Read an agent-named file for inspection, and pin it. None when it is
    outside the workdir, not a regular file, unreadable, or over the
    per-analysis budget: the caller treats that as uninspectable."""
    if not _within_workdir(path):
        return None
    pins = _PINS.get()
    if pins is not None and path in pins["files"]:
        cached = pins["data"].get(path)
        if cached is not None:
            return cast(bytes, cached)
    if pins is not None:
        if pins["files_opened"] >= MAX_FILES_PER_ANALYSIS:
            return None
        pins["files_opened"] += 1
    fd = _open_regular(path)
    if fd is None:
        return None
    try:
        with os.fdopen(fd, "rb") as fh:
            data = fh.read(MAX_INSPECT_BYTES)
            if pins is not None:
                _pin(fh, path, data, pins)
            return data
    except (OSError, ValueError):
        return None


def _pin(fh: Any, path: str, data: bytes, pins: dict[str, Any]) -> None:
    """Pin an open file by SHA-256 of all its bytes, from the same handle
    the guard inspected, within the per-analysis hash budget."""
    st = os.fstat(fh.fileno())
    h = hashlib.sha256(data)
    complete = len(data) < MAX_INSPECT_BYTES
    covers = complete
    budget = pins["hash_budget"] - len(data)
    if not complete and st.st_size <= min(MAX_PIN_BYTES, budget):
        for chunk in iter(lambda: fh.read(1_048_576), b""):
            h.update(chunk)
            budget -= len(chunk)
        covers = True
    pins["hash_budget"] = max(0, budget)
    pins["files"][path] = {
        "realpath": path,
        "sha256": h.hexdigest(),
        "size": st.st_size,
        "inspected_completely": complete,
        # False when the budget stopped the hash: run_pinned then refuses
        # to execute (fail closed).
        "hash_covers_file": covers,
    }
    pins["data"][path] = data


# ---- content-based secret detection (enterprise hardening, 2026-10-19) ----
# File names are not enough: a renamed .env or a pasted token has no telling
# name. These patterns are the high-precision public formats of common
# credentials, plus KEY=VALUE lines whose key names a secret. They apply to
# literal arguments always, and to file contents when PV_SHELL_WORKDIR is set.
_TOKEN_PATTERNS = re.compile(
    r"AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}"  # AWS access key id
    r"|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}"  # GitHub
    r"|glpat-[A-Za-z0-9_\-]{20,}"  # GitLab
    r"|xox[abposr]-[A-Za-z0-9\-]{10,}"  # Slack
    r"|(?:sk|rk)_live_[A-Za-z0-9]{20,}"  # Stripe live keys
    r"|sk-(?:proj-|ant-[a-z0-9]+-)?[A-Za-z0-9_\-]{32,}"  # OpenAI / Anthropic
    r"|AIza[0-9A-Za-z_\-]{35}"  # Google API key
    r"|npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_\-]{50,}"  # package registries
    r"|-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----"  # PEM private keys
    r"|eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"  # JWT
    r"|(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?)://[^\s:/@]+:[^\s/@]+@"
)
_SECRET_ASSIGNMENT = re.compile(
    r"^[ \t]*(?:export[ \t]+)?[\"']?[A-Za-z0-9_.\-]*"
    r"(?:SECRET|TOKEN|PASSW(?:OR)?D|PASSPHRASE|API[_\-]?KEY|PRIVATE[_\-]?KEY|"
    r"ACCESS[_\-]?KEY|CREDENTIAL|AUTH[_\-]?KEY|CLIENT[_\-]?SECRET)[A-Za-z0-9_.\-]*"
    r"[\"']?[ \t]*[=:][ \t]*[\"']?([A-Za-z0-9+/_\-.~=]{8,})[\"']?[ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)
_HIGH_ENTROPY_CANDIDATE = re.compile(r"[A-Za-z0-9+/_\-]{32,}={0,2}")
MIN_ENTROPY_BITS = 4.3


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _looks_random(word: str) -> bool:
    """A 32+ character token mixing upper case, lower case and digits with
    high Shannon entropy: an API key or bearer token, not a word, a path or
    a hex digest (hex digests are lower case only and stay below the bar)."""
    return (
        any(c.isupper() for c in word)
        and any(c.islower() for c in word)
        and any(c.isdigit() for c in word)
        and _entropy(word) >= MIN_ENTROPY_BITS
    )


def _assignment_is_secret(value: str) -> bool:
    if value.startswith(("$", "%", "<")) or value.lower() in {
        "true",
        "false",
        "none",
        "null",
        "changeme",
        "required",
        "optional",
    }:
        return False
    return not re.fullmatch(r"[a-z_]+(\.[a-z_]+)*", value)  # code identifiers


# Cheap substring pre-filters: the regexes only run when one could match,
# which keeps a large ordinary file at one linear scan per marker.
_TOKEN_MARKERS = (
    "AKIA", "ASIA", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
    "glpat-", "xox", "_live_", "sk-", "AIza", "npm_", "pypi-", "PRIVATE KEY",
    "eyJ", "://",
)  # fmt: skip
_ASSIGNMENT_MARKERS = (
    "secret", "token", "passw", "passphrase", "api", "private", "access",
    "credential", "auth", "client",
)  # fmt: skip


def content_reveals_secret(text: str, *, entropy: bool = False) -> bool:
    """True if text contains a credential by content, not by file name."""
    if any(m in text for m in _TOKEN_MARKERS) and _TOKEN_PATTERNS.search(text):
        return True
    lowered = text.lower()
    if any(m in lowered for m in _ASSIGNMENT_MARKERS) and any(
        _assignment_is_secret(m.group(1)) for m in _SECRET_ASSIGNMENT.finditer(text)
    ):
        return True
    if entropy:
        return any(
            _looks_random(m.group(0)) for m in _HIGH_ENTROPY_CANDIDATE.finditer(text)
        )
    return False


def _secret_material() -> tuple[
    frozenset[str], frozenset[str], frozenset[tuple[int, int]]
]:
    """(secret values, secret variable names, (dev, inode) of secret files).

    Values come from PV_SHELL_SECRET_FILES (KEY=VALUE lines, e.g. .env);
    variable names are those keys plus PV_SHELL_SECRET_VARS, plus any
    variable in this process environment whose value is a known secret.
    """
    files_env = os.environ.get(SECRET_FILES_ENV, "")
    stamp: list[tuple[str, int | None, int | None, int | None]] = []
    for raw in files_env.split(","):
        try:
            st = os.stat(raw.strip())
            stamp.append((raw, st.st_ino, st.st_mtime_ns, st.st_size))
        except OSError:
            stamp.append((raw, None, None, None))
    key = (files_env, os.environ.get(SECRET_VARS_ENV, ""), tuple(stamp))
    if _SECRET_CACHE.get("key") != key:
        _SECRET_CACHE["key"] = key
        _SECRET_CACHE["value"] = _load_secret_files(files_env)
    values, file_names, inodes = _SECRET_CACHE["value"]
    names = set(file_names) | {
        v.strip() for v in os.environ.get(SECRET_VARS_ENV, "").split(",") if v.strip()
    }
    if values:
        names |= {k for k, v in os.environ.items() if v and v in values}
    return values, frozenset(names), inodes


_SECRET_CACHE: dict[str, Any] = {}


def _load_secret_files(
    files_env: str,
) -> tuple[frozenset[str], frozenset[str], frozenset[tuple[int, int]]]:
    values: set[str] = set()
    names: set[str] = set()
    inodes: set[tuple[int, int]] = set()
    for raw in files_env.split(","):
        path = raw.strip()
        if not path:
            continue
        try:
            st = os.stat(path)
            inodes.add((st.st_dev, st.st_ino))
        except OSError:
            continue
        data = _read_operator_file(path) or b""
        for line in data.decode("utf-8", "replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip().removeprefix("export ").strip()
            val = val.strip().strip("'\"")
            if key:
                names.add(key)
            if len(val) >= MIN_SECRET_VALUE_CHARS:
                values.add(val)
    return frozenset(values), frozenset(names), frozenset(inodes)


def _is_secret_path(path: str) -> bool:
    """A real path that is credential-like by name, or is a configured
    secret file (same inode: hard links), or contains a known secret.
    Memoised per analysis: one command names the same file several ways."""
    pins = _PINS.get()
    cache = pins.setdefault("secret_path", {}) if pins is not None else None
    if cache is not None and path in cache:
        return bool(cache[path])
    verdict = _is_secret_path_uncached(path)
    if cache is not None:
        cache[path] = verdict
    return verdict


def _is_secret_path_uncached(path: str) -> bool:
    if _SENSITIVE.search(path):
        return True
    values, _, inodes = _secret_material()
    try:
        st = os.stat(path)
        if (st.st_dev, st.st_ino) in inodes:
            return True
    except OSError:
        return False
    if os.path.isfile(path):
        data = _read_limited(path) or b""
        text = data.decode("utf-8", "replace")
        if values and any(v in text for v in values):
            return True
        return content_reveals_secret(text)
    return False


_VAR_REF = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")
_QUOTED = re.compile(r"[\'\"]([^\'\"\n]{1,512})[\'\"]")


def _token_reveals_secret(token: str) -> bool:
    values, names, _ = _secret_material()
    if any(v in token for v in values):
        return True
    return any(m.group(1) in names for m in _VAR_REF.finditer(token))


def _note_fs_sensitive(token: str, acc: _Acc) -> bool:
    for part in dict.fromkeys(
        (token, token.split("=", 1)[-1], token.lstrip("@"), token.split("@", 1)[-1])
    ):
        real = _resolve(part)
        if real is not None and _is_secret_path(real):
            if token not in acc.sensitive_args:
                acc.sensitive_args.append(token)
            return True
    return False


# Language-level deletion APIs (Python, Perl, Ruby, Node, PHP, Go, Java).
_DESTRUCTIVE_API = re.compile(
    r"shutil\.rmtree|os\.(?:remove|unlink|rmdir|removedirs|truncate)\b"
    r"|\.(?:unlink|rmdir|rmtree)\(|send2trash"
    r"|\brmtree\b|\bremove_tree\b|\bunlink\s*[\(\"'$]|\brmdir\s*\("
    r"|FileUtils\.(?:rm|rm_r|rm_rf|rm_f|remove|remove_dir|remove_entry\w*)\b"
    r"|File\.(?:delete|unlink)\b|Dir\.(?:delete|rmdir|unlink)\b"
    r"|fs(?:\.promises)?\.(?:rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync|"
    r"truncate|truncateSync)\b|\b(?:rmSync|unlinkSync|rmdirSync|truncateSync)\b"
    r"|\bos\.RemoveAll\b|Files\.delete"
)
# The script hands strings to the OS to run.
_EXEC_API = re.compile(
    r"subprocess|os\.(?:system|popen|exec\w*|spawn\w*)|\bsystem\s*\(|\bexec\s*\("
    r"|child_process|execSync|spawnSync|Runtime\.getRuntime|`|\bqx\b|%x\{|IO\.popen"
    r"|shell_exec|passthru|proc_open|\bOpen3\b"
)
_SCRIPT_SUFFIX = re.compile(
    r"\.(?:py|pyw|sh|bash|zsh|ksh|js|mjs|cjs|ts|rb|pl|pm|php|lua|ps1|r)\Z",
    re.IGNORECASE,
)


def _quoted_command_is_destructive(q: str) -> bool:
    words = q.split()
    if not words:
        return False
    name = _canon(words[0])
    return name in DESTRUCTIVE or name.startswith("mkfs")


def _inspect_script(  # noqa: C901 - ordered checklist of script checks
    path_token: str, acc: _Acc, shell: bool = False
) -> None:
    """A script file an interpreter will run (operator set PV_SHELL_WORKDIR).

    Flags it if its text names a credential-like file, a known secret value,
    a secret variable or a credential by content (SHELL_SCRIPT_SECRET); if it
    deletes, truncates or overwrites files (SHELL_SCRIPT_DESTRUCTIVE); or if
    it is missing, unreadable or larger than the inspection limit
    (SHELL_SCRIPT_UNINSPECTABLE). Shell scripts are parsed like a command.
    """
    if _workdir() is None:
        return  # cannot see the agent's files: policy decides (held)
    real = _resolve(path_token)
    if real is None:
        if _SCRIPT_SUFFIX.search(path_token) or "/" in path_token:
            acc.script_uninspectable.append(path_token)  # does not exist yet
        return
    if not os.path.isfile(real):
        acc.script_uninspectable.append(path_token)
        return
    data = _read_limited(real)
    if data is None or len(data) >= MAX_INSPECT_BYTES:
        acc.script_uninspectable.append(path_token)
        return
    text = data.decode("utf-8", "replace")
    quoted = _QUOTED.findall(text)
    hits = [q for q in quoted if _SENSITIVE.search(q) or _note_fs_probe(q)]
    if hits or _token_reveals_secret(text) or content_reveals_secret(text):
        acc.script_secret.append(path_token)
    destructive = bool(_DESTRUCTIVE_API.search(text))
    if not destructive and _EXEC_API.search(text):
        destructive = any(_quoted_command_is_destructive(q) for q in quoted)
    if shell:
        sub = _Acc()
        body = "\n".join(
            ln for ln in text.splitlines() if not ln.lstrip().startswith("#")
        )
        try:
            _analyze_string(body, sub, 1)
        except _UnparseableError:
            acc.script_uninspectable.append(path_token)
        for exe in sub.executables:
            if exe not in acc.script_executables:
                acc.script_executables.append(exe)
        if sub.destructive_flags or any(
            e in DESTRUCTIVE or e.startswith("mkfs") for e in sub.executables
        ):
            destructive = True
        if sub.sensitive_args and any(e in NETWORK for e in sub.executables):
            acc.script_secret.append(path_token)
        acc.script_secret.extend(sub.script_secret)
        acc.script_destructive.extend(sub.script_destructive)
    if destructive:
        acc.script_destructive.append(path_token)


def _note_fs_probe(token: str) -> bool:
    real = _resolve(token)
    return real is not None and _is_secret_path(real)


def _curl_config(path_token: str, acc: _Acc) -> None:
    """curl -K FILE: the options live in the file. Inspect it like argv."""
    real = _resolve(path_token)
    data = _read_limited(real) if real else None
    if data is None:
        acc.inline_code = True  # options the runtime cannot see
        return
    for line in data.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for tok in re.split(r"[\s=:]+", line, maxsplit=1)[1:] or [line]:
            tok = tok.strip().strip("'\"")
            _note_sensitive(tok, acc)
            if tok.startswith("@"):
                acc.reads_files.append(tok[1:])
        if re.match(r"-?-?(upload-file|T)\b", line):
            target = re.split(r"[\s=:]+", line, maxsplit=1)[-1].strip().strip("'\"")
            acc.reads_files.append(target)


def _note_assignment(tok: str, acc: _Acc) -> None:
    name, _, value = tok.partition("=")
    acc.assigned[name] = _expand_vars(value, acc)
    if name in EXEC_ENV or name.startswith(EXEC_ENV_PREFIXES):
        acc.inline_code = True


def _expand_vars(token: str, acc: _Acc) -> str:
    """$NAME and ${NAME} replaced by values assigned earlier in the command;
    unknown names are left as written."""
    if "$" not in token or not acc.assigned:
        return token

    def sub(m: re.Match[str]) -> str:
        name = m.group(1) or m.group(2)
        return acc.assigned.get(name, m.group(0))

    return _VAR_USE.sub(sub, token)


def _expand_braces(token: str, limit: int = 64) -> list[str]:
    """Shell brace expansion ({a,b}), enough to see ".{e,x}nv" as ".env"."""
    out: list[str] = []
    todo = [token]
    while todo and len(out) + len(todo) <= limit:
        cur = todo.pop()
        m = _BRACES.search(cur)
        if m is None:
            out.append(cur)
            continue
        for alt in m.group(1).split(","):
            todo.append(cur[: m.start()] + alt + cur[m.end() :])
    return out + todo


def _glob_hits_secret(variant: str, wd: str) -> bool:
    """Expand a relative pattern inside the workdir; any credential hit,
    an error, or too many hits to judge counts as sensitive."""
    try:
        hits = glob.iglob(os.path.join(glob.escape(wd), variant))
        for n, hit in enumerate(hits):
            if n >= MAX_GLOB_HITS:
                return True
            real = os.path.realpath(hit)
            if _within_workdir(real) and (
                _SENSITIVE.search(real) or _is_secret_path(real)
            ):
                return True
    except (OSError, ValueError, re.error):
        return True
    return False


def _name_could_match(variant: str) -> bool:
    """Could a path component of this glob match a credential-like name?
    As in the shell, a pattern not starting with "." skips dotfiles."""
    for comp in variant.split("/"):
        if not _GLOB_CHARS.search(comp):
            continue
        for name in _SENSITIVE_NAMES:
            if name.startswith(".") and not comp.startswith("."):
                continue
            if fnmatch.fnmatchcase(name.lower(), comp.lower()):
                return True
    return False


def _pattern_sensitive(pattern: str) -> bool:
    """Could this glob or brace pattern name a credential? Inside the
    workdir it is expanded against the real files; elsewhere it is matched
    against credential-like names (red team 2026-10-23, F5)."""
    wd = _workdir()
    for variant in _expand_braces(pattern):
        if _SENSITIVE.search(variant):
            return True
        if not _GLOB_CHARS.search(variant):
            continue
        local = wd is not None and not os.path.isabs(variant) and "~" not in variant
        if (
            _glob_hits_secret(variant, wd)
            if local and wd
            else _name_could_match(variant)
        ):
            return True
    return False


def _note_sensitive(token: str, acc: _Acc) -> None:
    token = _expand_vars(token, acc)
    if _token_reveals_secret(token) or content_reveals_secret(
        token, entropy="://" not in token
    ):
        if token not in acc.sensitive_args:
            acc.sensitive_args.append(token)
        return
    if _note_fs_sensitive(token, acc):
        return
    if _SECRET_VAR.search(token):
        if token not in acc.sensitive_args:
            acc.sensitive_args.append(token)
        return
    if "://" in token:
        return  # a URL, not a local file
    # name@file (curl --data-urlencode) and @file forms, external retest N16;
    # rev:path (git show HEAD:.env), red team 2026-10-23 F9
    for part in (
        token,
        token.split("=", 1)[-1],
        token.lstrip("@"),
        token.split("@", 1)[-1],
        token.split(":", 1)[-1],
        token.rsplit(":", 1)[-1],
    ):
        if part and (_SENSITIVE.search(part) or _pattern_sensitive(part)):
            if token not in acc.sensitive_args:
                acc.sensitive_args.append(token)
            return


def _skip_wrapper(name: str, argv: list[str], acc: _Acc | None = None) -> list[str]:
    """Return the wrapped command's argv (may be empty)."""
    with_arg = _OPTS_WITH_ARG.get(name, frozenset())
    i, n = 1, len(argv)
    leading_param = name in _LEADING_PARAM
    while i < n:
        tok = argv[i]
        if tok == "--":
            i += 1
            break
        if tok.startswith("-") and tok != "-":
            i += 2 if tok in with_arg else 1
            continue
        if name == "env" and _ASSIGNMENT.match(tok):
            if acc is not None:
                _note_assignment(tok, acc)
            i += 1
            continue
        if leading_param:
            leading_param = False
            i += 1
            continue
        if name in {"nice", "ionice"} and tok.lstrip("-").isdigit():
            i += 1
            continue
        break
    return argv[i:]


def _curl_wget_reads(  # noqa: C901 - ordered option checklist
    name: str, argv: list[str], acc: _Acc
) -> None:
    data_opts = {"-d", "--data", "--data-binary", "--data-ascii", "--data-urlencode"}
    i = 1
    while i < len(argv):
        tok = argv[i]
        nxt = argv[i + 1] if i + 1 < len(argv) else ""
        if name == "curl":
            if tok in data_opts and nxt.startswith("@"):
                acc.reads_files.append(nxt[1:])
            elif tok == "--data-urlencode" and "@" in nxt:
                # name@file or @file: curl reads and sends the file
                acc.reads_files.append(nxt.split("@", 1)[1])
            elif tok in {"-F", "--form"} and "=@" in nxt:
                acc.reads_files.append(nxt.split("=@", 1)[1].split(";", 1)[0])
            elif tok in {"-T", "--upload-file"} and nxt:
                acc.reads_files.append(nxt)
            elif tok.startswith("-d@") or tok.startswith("--data-binary=@"):
                acc.reads_files.append(tok.split("@", 1)[1])
            elif tok in {"-K", "--config"} and nxt:
                _curl_config(nxt, acc)
            elif tok.startswith("--config="):
                _curl_config(tok.split("=", 1)[1], acc)
        else:
            for opt in ("--post-file", "--body-file"):
                if tok == opt and nxt:
                    acc.reads_files.append(nxt)
                elif tok.startswith(opt + "="):
                    acc.reads_files.append(tok.split("=", 1)[1])
        i += 1


_SHELL_C = re.compile(r"-[A-Za-z]*c[A-Za-z]*\Z")
_SHELL_OPT_ARG = frozenset({"-o", "+o", "-O", "+O", "--rcfile", "--init-file"})


def _shell_script(argv: list[str]) -> tuple[str | None, bool]:
    """(-c script or None, has a script-file operand).

    Deliberately conservative: a -c flag anywhere counts, so option order
    (``bash -o pipefail -c ...``) cannot hide it.
    """
    for j, tok in enumerate(argv[1:], 1):
        if _SHELL_C.match(tok):
            if j + 1 >= len(argv):
                raise _UnparseableError("shell -c without a command")
            return argv[j + 1], True
    j = 1
    while j < len(argv):
        tok = argv[j]
        if tok in _SHELL_OPT_ARG:
            j += 2
            continue
        if tok.startswith(("-", "+")):
            j += 1
            continue
        return None, True
    return None, False


def _has_inline_flag(name: str, args: list[str]) -> bool:
    flags = INLINE_FLAGS.get(name, frozenset())
    for raw in args:
        tok = raw.lower()
        for flag in flags:
            if tok == flag or tok.startswith(flag + "="):
                return True
            # short flag clustered or with attached code: -Sc, -e'print 1'
            if len(flag) == 2 and re.match(r"-[a-z]*" + re.escape(flag[1]), tok):
                return True
    return False


def _analyze_argv(argv: list[str], acc: _Acc, depth: int) -> None:  # noqa: C901
    if depth > MAX_DEPTH:
        raise _UnparseableError("nesting exceeds limit")
    while argv and _ASSIGNMENT.match(argv[0]):
        _note_assignment(argv[0], acc)
        argv = argv[1:]
    if not argv:
        return
    for tok in argv[1:]:
        _note_sensitive(tok, acc)
    name = _canon(_expand_vars(argv[0], acc))
    acc.note_exe(name)

    if name == "uv":
        _uv(argv, acc, depth)
        return
    if name == "uvx":
        acc.interpreter = True  # fetches and runs a package's code
        return
    if name == "git":
        _git(argv, acc, depth)

    if name in WRAPPERS:
        if name == "busybox" and len(argv) > 1:
            _analyze_argv(argv[1:], acc, depth + 1)
            return
        if name == "env":
            for j, tok in enumerate(argv[1:], 1):
                if tok in {"-S", "--split-string"} and j + 1 < len(argv):
                    acc.inline_code = True
                    _analyze_string(argv[j + 1], acc, depth + 1)
                    return
        inner = _skip_wrapper(name, argv, acc)
        if not inner and name == "env":
            acc.sensitive_args.append("env")  # bare env dumps every secret
        if inner:
            _analyze_argv(inner, acc, depth + 1)
        elif name in {"sudo", "doas"} and any(t in {"-s", "-i"} for t in argv[1:]):
            acc.interpreter = True
            acc.inline_code = True
        return

    if name in SHELLS:
        acc.interpreter = True
        script, has_file = _shell_script(argv)
        if script is not None:
            acc.inline_code = True
            _analyze_string(script, acc, depth + 1)
        elif not has_file:
            acc.inline_code = True  # commands come from stdin / heredoc
        else:
            script = next((t for t in argv[1:] if not t.startswith(("-", "+"))), None)
            if script is not None:
                _inspect_script(script, acc, shell=True)
        return

    if name in INTERPRETERS:
        acc.interpreter = True
        if _has_inline_flag(name, argv[1:]):
            acc.inline_code = True
        elif name in {"awk", "gawk", "deno", "bun"}:
            acc.inline_code = True  # program text is an argument
        elif len(argv) == 1 or "-" in argv[1:]:
            acc.inline_code = True  # reads program from stdin
        elif name == "python" and any(
            t == "-m" or t.startswith("-m") for t in argv[1:]
        ):
            pass  # module run: code comes from sys.path, policy decides
        else:
            script = next((t for t in argv[1:] if not t.startswith("-")), None)
            if script is not None:
                _inspect_script(script, acc)
        return

    if name in EVAL_WORDS:
        acc.inline_code = True
        return

    if name == "printenv":
        acc.sensitive_args.append(name)  # dumps every secret in the env
        return

    if name == "tar" and any(t == "--remove-files" for t in argv[1:]):
        acc.destructive_flags = True
    if name == "rsync" and any(
        t == "--remove-source-files" or t.startswith("--delete") for t in argv[1:]
    ):
        acc.destructive_flags = True

    if name == "find":
        for j, tok in enumerate(argv):
            if tok == "-delete":
                acc.destructive_flags = True
            if tok in {"-exec", "-execdir", "-ok", "-okdir"}:
                end = j + 1
                while end < len(argv) and argv[end] not in {";", "+", "\\;"}:
                    end += 1
                _analyze_argv(argv[j + 1 : end], acc, depth + 1)
        return

    if name in {"watch"}:
        acc.inline_code = True
        _analyze_string(" ".join(_skip_wrapper("watch", argv)), acc, depth + 1)
        return

    if name in {"curl", "wget"}:
        _curl_wget_reads(name, argv, acc)


def _uv_run_target(argv: list[str]) -> tuple[list[str], bool]:
    """(what "uv run ..." runs, whether it is a module) after its options."""
    i = 2
    while i < len(argv):
        tok = argv[i]
        if tok == "--":
            return argv[i + 1 :], False
        if tok in {"-m", "--module"}:
            return argv[i + 1 :], True
        if tok in {"-s", "--script"}:
            return argv[i + 1 :], False
        if not tok.startswith("-"):
            break
        i += 2 if tok in _UV_RUN_OPTS_WITH_ARG else 1
    return argv[i:], False


def _uv(argv: list[str], acc: _Acc, depth: int) -> None:
    """uv run judged by what it runs (red team 2026-10-23, F4): "uv run
    python -c ..." is inline code, "uv run x.py" is a python script."""
    sub = argv[1] if len(argv) > 1 else ""
    if sub == "run":
        inner, module = _uv_run_target(argv)
        if module:
            _analyze_argv(["python", "-m", *inner], acc, depth + 1)
        elif inner and inner[0].lower().endswith((".py", ".pyw")):
            _analyze_argv(["python", *inner], acc, depth + 1)
        elif inner:
            _analyze_argv(inner, acc, depth + 1)
    elif sub in _UV_INSTALLS:
        acc.interpreter = True  # installing runs package build code


def _git_key_safe(key: str) -> bool:
    key = key.strip().lower()
    return any(
        key == p or (p.endswith(".") and key.startswith(p)) for p in _GIT_SAFE_KEYS
    )


def _git(argv: list[str], acc: _Acc, depth: int) -> None:  # noqa: C901
    """git options and subcommands that run other programs (red team
    2026-10-23, F3): -c core.pager=..., --config-env, --upload-pack,
    ext:: transports, rebase --exec, bisect run, submodule foreach, and
    git config writing a key that can run code."""
    i, n = 1, len(argv)
    while i < n:
        tok = argv[i]
        if tok == "-c":
            if i + 1 >= n or not _git_key_safe(argv[i + 1].split("=", 1)[0]):
                acc.inline_code = True
            i += 2
            continue
        if tok.startswith("-c") and len(tok) > 2:
            if not _git_key_safe(tok[2:].split("=", 1)[0]):
                acc.inline_code = True
            i += 1
            continue
        if tok.startswith(("--config-env", "--exec-path")):
            acc.inline_code = True
            i += 1
            continue
        if tok in _GIT_OPTS_WITH_ARG:
            i += 2
            continue
        if tok.startswith("-"):
            i += 1
            continue
        break
    sub = argv[i] if i < n else ""
    rest = argv[i + 1 :]
    for j, tok in enumerate(rest):
        nxt = rest[j + 1] if j + 1 < len(rest) else ""
        if (
            tok.startswith(("ext::", "--upload-pack", "--receive-pack", "--exec="))
            or (tok == "--exec" and sub in {"archive", "push", "send-pack"})
            or (tok == "-u" and sub in {"clone", "ls-remote"})
        ):
            acc.inline_code = True  # names a program for git to run
        elif tok in {"-c", "--config"} and sub == "clone":
            if not _git_key_safe(nxt.split("=", 1)[0]):
                acc.inline_code = True
        elif tok.startswith("--config=") and sub == "clone":
            if not _git_key_safe(tok.split("=", 1)[1].split("=", 1)[0]):
                acc.inline_code = True
        elif sub == "rebase" and tok in {"-x", "--exec"}:
            _analyze_string(nxt, acc, depth + 1)
            acc.inline_code = True
        elif sub in {"difftool", "mergetool"} and (
            tok in {"-x", "--extcmd"} or tok.startswith("--extcmd=")
        ):
            acc.inline_code = True
    if sub == "clean":
        acc.destructive_flags = True
    elif sub == "bisect" and "run" in rest:
        acc.inline_code = True
        _analyze_argv(rest[rest.index("run") + 1 :], acc, depth + 1)
    elif sub == "submodule" and "foreach" in rest:
        acc.inline_code = True
    elif sub in {"filter-branch", "filter-repo"}:
        acc.inline_code = True
    elif sub == "config":
        opts = [t for t in rest if t.startswith("-")]
        args = [t for t in rest if not t.startswith("-")]
        reading = any(
            o in {"--get", "--get-all", "--get-regexp", "-l", "--list", "--show-origin"}
            for o in opts
        ) or (args[:1] in (["get"], ["list"]))
        if args and args[0] in {"set", "unset", "get", "list"}:
            args = args[1:]
        if not reading and len(args) >= 2 and not _git_key_safe(args[0]):
            acc.inline_code = True  # persists a key that runs code later
        if not reading and any(o in {"--add", "--replace-all"} for o in opts):
            if not args or not _git_key_safe(args[0]):
                acc.inline_code = True


def _analyze_string(command: str, acc: _Acc, depth: int) -> None:  # noqa: C901
    if depth > MAX_DEPTH:
        raise _UnparseableError("nesting exceeds limit")
    if len(command) > MAX_COMMAND_CHARS:
        raise _UnparseableError("command too long")
    if "\x00" in command:
        raise _UnparseableError("NUL byte in command")
    if any(m in command for m in ("`", "$(", "<(", ">(")):
        acc.inline_code = True  # command / process substitution
    # Newline is a command separator in shell, not whitespace: without this
    # "ls\nrm -rf x" would read as one command whose arguments hide rm.
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>()\n")
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        tokens = list(lexer)
    except ValueError as exc:
        raise _UnparseableError(f"shell syntax: {exc}") from exc
    segment: list[str] = []
    i = 0
    while i < len(tokens) + 1:
        tok = tokens[i] if i < len(tokens) else ";"
        if tok in _CONTROL or set(tok) <= set(";&|()\n"):
            if tok != ";" or i < len(tokens):
                acc.operators = True
            _analyze_argv([t for t in segment if t not in _KEYWORDS], acc, depth)
            segment = []
            i += 1
            continue
        if tok in _REDIRECT_IN or tok in _REDIRECT_OUT or tok == "<<":
            acc.operators = True
            target = tokens[i + 1] if i + 1 < len(tokens) else ""
            if tok in _REDIRECT_IN and target:
                acc.reads_files.append(target)
                _note_sensitive(target, acc)
            elif tok in _REDIRECT_OUT and target:
                acc.writes_files.append(target)
            i += 2
            continue
        if not segment and tok in _KEYWORDS:
            i += 1
            continue
        segment.append(tok)
        i += 1


def _argv_from_arguments(arguments: Mapping[str, Any]) -> tuple[str, Any]:
    """('argv', list) or ('string', str). Raises _UnparseableError."""
    argv = arguments.get("argv")
    if argv is not None:
        if not isinstance(argv, list) or not argv:
            raise _UnparseableError("argv must be a non-empty list of strings")
        if not all(isinstance(t, str) for t in argv):
            raise _UnparseableError("argv must be a non-empty list of strings")
        return "argv", list(argv)
    command = arguments.get("command", arguments.get("cmd"))
    args = arguments.get("args")
    if isinstance(command, list):
        if command and all(isinstance(t, str) for t in command):
            return "argv", list(command)
        raise _UnparseableError("command list must contain strings")
    if isinstance(command, str) and command.strip():
        if args is not None:
            if not isinstance(args, list) or not all(isinstance(t, str) for t in args):
                raise _UnparseableError("args must be a list of strings")
            return "argv", [command, *args]
        return "string", command
    raise _UnparseableError("no argv, command or cmd argument")


def shell_command(arguments: Mapping[str, Any]) -> tuple[str, Any]:
    """('argv', list) or ('string', str) for a shell action's arguments, as
    the guard reads them. ValueError if they describe no command."""
    try:
        return _argv_from_arguments(arguments)
    except _UnparseableError as exc:
        raise ValueError(str(exc)) from exc


def analyze_shell_arguments(arguments: Mapping[str, Any] | None) -> dict[str, Any]:
    """Derive ``evidence.shell`` from a shell action's arguments. Total."""
    acc = _Acc()
    error: str | None = None
    form = None
    pins: dict[str, Any] = {
        "files": {},
        "tokens": {},
        "data": {},
        "files_opened": 0,
        "hash_budget": MAX_HASH_BYTES_PER_ANALYSIS,
    }
    reset = _PINS.set(pins)
    try:
        try:
            form, value = _argv_from_arguments(arguments or {})
            if form == "argv":
                _analyze_argv(value, acc, 0)
            else:
                _analyze_string(value, acc, 0)
        except _UnparseableError as exc:
            error = str(exc)
        reads = list(dict.fromkeys(acc.reads_files))
        sensitive_reads = [
            p for p in reads if _SENSITIVE.search(p) or _note_fs_probe(p)
        ]
    finally:
        _PINS.reset(reset)
    pinned = [
        {**info, "tokens": sorted(set(pins["tokens"].get(real, [])))}
        for real, info in sorted(pins["files"].items())
    ]
    network = any(e in NETWORK for e in acc.executables)
    return {
        "parse_ok": error is None,
        "error": error,
        "form": form,
        "primary": acc.executables[0] if acc.executables else None,
        "executables": list(acc.executables),
        "inline_code": acc.inline_code,
        "interpreter": acc.interpreter,
        "operators": acc.operators,
        "network": network,
        "destructive": acc.destructive_flags
        or bool(acc.script_destructive)
        or any(e in DESTRUCTIVE or e.startswith("mkfs") for e in acc.executables),
        "reads_files": reads,
        "writes_files": list(dict.fromkeys(acc.writes_files)),
        "touches_sensitive": bool(acc.sensitive_args or sensitive_reads),
        "secret_egress": network and bool(acc.sensitive_args or sensitive_reads),
        "script_secret": list(dict.fromkeys(acc.script_secret)),
        "script_destructive": list(dict.fromkeys(acc.script_destructive)),
        "script_uninspectable": list(dict.fromkeys(acc.script_uninspectable)),
        "script_executables": list(acc.script_executables),
        # TOCTOU: every file the guard read, pinned by SHA-256. The record
        # seals these; agent_dna.shell_pin re-checks them at execution.
        "pinned_files": pinned,
        "secret_staging": bool(acc.sensitive_args or sensitive_reads)
        and (any(e in STAGING for e in acc.executables) or bool(acc.writes_files)),
    }


def attach_shell_evidence(
    capability: str,
    arguments: Mapping[str, Any] | None,
    evidence: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    """Return evidence with ``shell`` server-derived (shell capabilities) or
    removed (everything else). Callers never author ``evidence.shell``."""
    out = dict(evidence or {})
    out.pop("shell", None)
    if capability in shell_capabilities():
        out["shell"] = analyze_shell_arguments(arguments)
    return out or None


def block_destructive_by_default() -> bool:
    """Destructive programs are a built-in BLOCK, with no policy, when
    ``PV_SHELL_BLOCK_DESTRUCTIVE=1``, or under ``PV_SECURE_PROFILE`` unless
    ``PV_SHELL_BLOCK_DESTRUCTIVE=0``. Otherwise they are evidence for policy
    (``examples/config/shell-policy.json``)."""
    raw = os.environ.get(BLOCK_DESTRUCTIVE_ENV, "").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return os.environ.get("PV_SECURE_PROFILE", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def shell_findings(shell: Mapping[str, Any] | None) -> list[tuple[str, str]]:
    if not shell:
        return []
    findings: list[tuple[str, str]] = []
    if shell.get("destructive") and block_destructive_by_default():
        findings.append(
            (
                SHELL_DESTRUCTIVE,
                "command deletes, truncates, overwrites or re-permissions files "
                "(destructive program, flag or script); blocked by default under "
                "the secure profile",
            )
        )
    if not shell.get("parse_ok"):
        findings.append(
            (SHELL_UNPARSEABLE, f"command could not be analysed ({shell.get('error')})")
        )
    if shell.get("inline_code") and os.environ.get(ALLOW_INLINE_ENV) != "1":
        findings.append(
            (
                SHELL_INLINE_CODE,
                "command runs code the runtime cannot inspect "
                "(sh -c, interpreter -c/-e, eval, $(...), a shell reading stdin, "
                "or git or environment settings that run a program)",
            )
        )
    if shell.get("secret_egress"):
        findings.append(
            (
                SHELL_SECRET_EGRESS,
                "network tool handed a credential (by name, value or content)",
            )
        )
    if shell.get("script_secret"):
        findings.append(
            (
                SHELL_SCRIPT_SECRET,
                "script file names a credential-like file or a known secret",
            )
        )
    if (
        shell.get("script_destructive")
        and os.environ.get(ALLOW_DESTRUCTIVE_SCRIPTS_ENV) != "1"
    ):
        findings.append(
            (
                SHELL_SCRIPT_DESTRUCTIVE,
                "script file deletes, truncates or removes files "
                "(content inspected: " + ", ".join(shell["script_destructive"]) + ")",
            )
        )
    if shell.get("script_uninspectable"):
        findings.append(
            (
                SHELL_SCRIPT_UNINSPECTABLE,
                "script file is missing, unreadable, not a regular file or larger "
                "than the inspection limit, so its content cannot be checked",
            )
        )
    if shell.get("secret_staging"):
        findings.append(
            (
                SHELL_SECRET_STAGING,
                "credential-like file copied, linked, packed or re-encoded",
            )
        )
    return findings


def escalate_with_shell(
    result: DecisionResult, shell: Mapping[str, Any] | None
) -> DecisionResult:
    """BLOCK on any shell-guard finding. Never relaxes an existing verdict."""
    findings = shell_findings(shell)
    if not findings or result.decision is Decision.BLOCK:
        return result
    return DecisionResult(
        decision=Decision.BLOCK,
        triggered_by=TRIGGERED_BY_SHELL,
        reason="; ".join(f"{code}: {detail}" for code, detail in findings),
        capability=result.capability,
        agent_id=result.agent_id,
        drift_score=result.drift_score,
        severity=Severity.CRITICAL,
        advisory_reasons=list(result.advisory_reasons),
        evidence=result.evidence,
        grant_id=result.grant_id,
    )


def attach_shell_record_item(
    result: DecisionResult, shell: Mapping[str, Any] | None
) -> DecisionResult:
    """Put the server-derived shell evidence (findings, programs, pinned
    file digests) into the decision's evidence items, which the decision
    record seals: it is covered by the record hash, the chain and the
    signature, and returned to the agent in the /v1/decide response.
    ``agent_dna.shell_pin`` reads the pins from there."""
    if not shell:
        return result
    payload = json.dumps(
        {**dict(shell), "findings": [c for c, _ in shell_findings(shell)]},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    item = EvidenceItem(
        name=SHELL_EVIDENCE_ITEM, score=1.0, confidence=1.0, summary=payload
    )
    if result.evidence is None:
        result.evidence = EvidenceReport(items=[item])
    else:
        result.evidence.items = [
            i for i in result.evidence.items if i.name != SHELL_EVIDENCE_ITEM
        ]
        result.evidence.add(item)
    return result
