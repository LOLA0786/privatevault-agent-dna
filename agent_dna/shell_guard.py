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

import os
import re
import shlex
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .advisory import Severity
from .decision import Decision, DecisionResult

SHELL_CAPABILITIES_ENV = "PV_SHELL_CAPABILITIES"
ALLOW_INLINE_ENV = "PV_SHELL_ALLOW_INLINE"
DEFAULT_SHELL_CAPABILITIES = frozenset({"shell.exec"})
TRIGGERED_BY_SHELL = "shell_guard"

SHELL_UNPARSEABLE = "SHELL_UNPARSEABLE"
SHELL_INLINE_CODE = "SHELL_INLINE_CODE"
SHELL_SECRET_EGRESS = "SHELL_SECRET_EGRESS"
SHELL_SECRET_STAGING = "SHELL_SECRET_STAGING"

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
    r"id_(rsa|dsa|ecdsa|ed25519)[^/]*|credentials(\.json)?|[^/]*\.(pem|key|p12|pfx))$"
    r"|(^|/)\.(ssh|aws|gnupg|kube|docker)(/|$)"
    r"|secret",
    re.IGNORECASE,
)


class _UnparseableError(ValueError):
    pass


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


def _note_sensitive(token: str, acc: _Acc) -> None:
    if "://" in token:
        return  # a URL, not a local file
    for part in (token, token.split("=", 1)[-1], token.lstrip("@")):
        if part and _SENSITIVE.search(part):
            if token not in acc.sensitive_args:
                acc.sensitive_args.append(token)
            return


def _skip_wrapper(name: str, argv: list[str]) -> list[str]:
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


def _curl_wget_reads(name: str, argv: list[str], acc: _Acc) -> None:
    data_opts = {"-d", "--data", "--data-binary", "--data-ascii", "--data-urlencode"}
    i = 1
    while i < len(argv):
        tok = argv[i]
        nxt = argv[i + 1] if i + 1 < len(argv) else ""
        if name == "curl":
            if tok in data_opts and nxt.startswith("@"):
                acc.reads_files.append(nxt[1:])
            elif tok in {"-F", "--form"} and "=@" in nxt:
                acc.reads_files.append(nxt.split("=@", 1)[1].split(";", 1)[0])
            elif tok in {"-T", "--upload-file"} and nxt:
                acc.reads_files.append(nxt)
            elif tok.startswith("-d@") or tok.startswith("--data-binary=@"):
                acc.reads_files.append(tok.split("@", 1)[1])
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
        argv = argv[1:]
    if not argv:
        return
    for tok in argv[1:]:
        _note_sensitive(tok, acc)
    name = _canon(argv[0])
    acc.note_exe(name)

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
        inner = _skip_wrapper(name, argv)
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
        return

    if name in INTERPRETERS:
        acc.interpreter = True
        if _has_inline_flag(name, argv[1:]):
            acc.inline_code = True
        elif name in {"awk", "gawk", "deno", "bun"}:
            acc.inline_code = True  # program text is an argument
        elif len(argv) == 1 or "-" in argv[1:]:
            acc.inline_code = True  # reads program from stdin
        return

    if name in EVAL_WORDS:
        acc.inline_code = True
        return

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


def analyze_shell_arguments(arguments: Mapping[str, Any] | None) -> dict[str, Any]:
    """Derive ``evidence.shell`` from a shell action's arguments. Total."""
    acc = _Acc()
    error: str | None = None
    form = None
    try:
        form, value = _argv_from_arguments(arguments or {})
        if form == "argv":
            _analyze_argv(value, acc, 0)
        else:
            _analyze_string(value, acc, 0)
    except _UnparseableError as exc:
        error = str(exc)
    reads = list(dict.fromkeys(acc.reads_files))
    sensitive_reads = [p for p in reads if _SENSITIVE.search(p)]
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
        or any(e in DESTRUCTIVE or e.startswith("mkfs") for e in acc.executables),
        "reads_files": reads,
        "writes_files": list(dict.fromkeys(acc.writes_files)),
        "touches_sensitive": bool(acc.sensitive_args or sensitive_reads),
        "secret_egress": network and bool(acc.sensitive_args or sensitive_reads),
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


def shell_findings(shell: Mapping[str, Any] | None) -> list[tuple[str, str]]:
    if not shell:
        return []
    findings: list[tuple[str, str]] = []
    if not shell.get("parse_ok"):
        findings.append(
            (SHELL_UNPARSEABLE, f"command could not be analysed ({shell.get('error')})")
        )
    if shell.get("inline_code") and os.environ.get(ALLOW_INLINE_ENV) != "1":
        findings.append(
            (
                SHELL_INLINE_CODE,
                "command runs code the runtime cannot inspect "
                "(sh -c, interpreter -c/-e, eval, $(...), or a shell reading stdin)",
            )
        )
    if shell.get("secret_egress"):
        findings.append(
            (SHELL_SECRET_EGRESS, "network tool handed a credential-like file")
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
