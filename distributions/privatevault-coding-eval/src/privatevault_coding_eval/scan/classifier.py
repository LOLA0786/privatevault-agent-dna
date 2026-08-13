"""Deterministic privacy-safe classification of coding-agent tool calls."""

from __future__ import annotations

import hashlib
import json
import shlex
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Classification:
    capability: str
    sink_id: str | None
    rule_id: str


_TOOL_RULES: dict[str, Classification] = {
    "Read": Classification(
        "repository.read",
        None,
        "tool.read",
    ),
    "Grep": Classification(
        "repository.search",
        None,
        "tool.grep",
    ),
    "Glob": Classification(
        "repository.search",
        None,
        "tool.glob",
    ),
    "Edit": Classification(
        "source.write",
        None,
        "tool.edit",
    ),
    "Write": Classification(
        "source.write",
        None,
        "tool.write",
    ),
    "NotebookEdit": Classification(
        "source.write",
        None,
        "tool.notebook-edit",
    ),
    "WebFetch": Classification(
        "network.read",
        None,
        "tool.web-fetch",
    ),
    "WebSearch": Classification(
        "network.read",
        None,
        "tool.web-search",
    ),
    "Agent": Classification(
        "agent.spawn",
        None,
        "tool.agent",
    ),
}


def digest_json(value: Any) -> str:
    """Digest tool input without retaining the raw payload."""

    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()

    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def pseudonymous_id(
    prefix: str,
    value: str,
) -> str:
    """Produce a stable non-reversible local identifier."""

    digest = hashlib.sha256(value.encode()).hexdigest()[:24]

    return f"{prefix}:{digest}"


def _segments(
    command: str,
) -> tuple[tuple[str, ...], ...]:
    lexer = shlex.shlex(
        command,
        posix=True,
        punctuation_chars=";&|",
    )
    lexer.whitespace_split = True
    lexer.commenters = ""

    segments: list[tuple[str, ...]] = []
    current: list[str] = []

    try:
        tokens = list(lexer)
    except ValueError:
        return ()

    for token in tokens:
        if token and set(token) <= {
            ";",
            "&",
            "|",
        }:
            if current:
                segments.append(tuple(current))
                current = []
        else:
            current.append(token)

    if current:
        segments.append(tuple(current))

    return tuple(segments)


def _unwrap(
    tokens: Sequence[str],
) -> tuple[str, ...]:
    result = list(tokens)

    while result and result[0] in {
        "sudo",
        "command",
        "nohup",
    }:
        result.pop(0)

    if result and result[0] == "env":
        result.pop(0)

        while (
            result
            and "=" in result[0]
            and not result[0].startswith(
                (
                    "./",
                    "/",
                )
            )
        ):
            result.pop(0)

    while (
        result
        and "=" in result[0]
        and not result[0].startswith(
            (
                "./",
                "/",
            )
        )
    ):
        result.pop(0)

    return tuple(result)


def _git(
    tokens: Sequence[str],
) -> Classification | None:
    if not tokens or tokens[0] != "git" or "push" not in tokens:
        return None

    push_index = tokens.index("push")
    options = tokens[push_index + 1 :]

    forced = any(
        token == "-f"
        or token == "--force"
        or token.startswith("--force=")
        or token.startswith("--force-with-lease")
        for token in options
    )

    if forced:
        return Classification(
            "git.push.force",
            "sink:git-push-force",
            "bash.git-push-force",
        )

    return Classification(
        "git.push",
        None,
        "bash.git-push",
    )


def _package_publish(
    tokens: Sequence[str],
) -> Classification | None:
    starts = (
        (
            "npm",
            "publish",
        ),
        (
            "pnpm",
            "publish",
        ),
        (
            "yarn",
            "npm",
            "publish",
        ),
        (
            "cargo",
            "publish",
        ),
        (
            "poetry",
            "publish",
        ),
        (
            "twine",
            "upload",
        ),
        (
            "gem",
            "push",
        ),
        (
            "dotnet",
            "nuget",
            "push",
        ),
    )

    matched = any(tuple(tokens[: len(prefix)]) == prefix for prefix in starts)

    python_twine = len(tokens) >= 4 and tuple(tokens[:4]) == (
        "python",
        "-m",
        "twine",
        "upload",
    )

    if matched or python_twine:
        return Classification(
            "package.publish",
            "sink:package-publish",
            "bash.package-publish",
        )

    return None


def _sensitive(
    tokens: Sequence[str],
) -> Classification | None:
    if not tokens:
        return None

    if tokens[0] == "terraform" and "destroy" in tokens:
        return Classification(
            "infrastructure.destroy",
            "sink:infrastructure-destroy",
            "bash.terraform-destroy",
        )

    if tokens[0] == "kubectl" and "delete" in tokens:
        return Classification(
            "infrastructure.delete",
            "sink:infrastructure-delete",
            "bash.kubectl-delete",
        )

    recursive_remove = tokens[0] == "rm" and any(
        token.startswith("-") and "r" in token for token in tokens[1:]
    )

    if recursive_remove:
        return Classification(
            "filesystem.destructive",
            "sink:filesystem-destructive",
            "bash.recursive-remove",
        )

    if tokens[0] == "ssh":
        return Classification(
            "remote.command.execute",
            "sink:remote-command",
            "bash.ssh",
        )

    secret_prefixes = (
        (
            "aws",
            "secretsmanager",
            "get-secret-value",
        ),
        (
            "vault",
            "kv",
            "get",
        ),
        (
            "gh",
            "secret",
        ),
        ("printenv",),
    )

    secret_access = any(
        tuple(tokens[: len(prefix)]) == prefix for prefix in secret_prefixes
    )

    if secret_access:
        return Classification(
            "secrets.read",
            "sink:secrets-read",
            "bash.secrets-read",
        )

    return None


def _routine(
    tokens: Sequence[str],
) -> Classification:
    if not tokens:
        return Classification(
            "command.execute.unknown",
            None,
            "bash.unparsed",
        )

    test_prefixes = {
        (
            "npm",
            "test",
        ),
        (
            "pnpm",
            "test",
        ),
        (
            "cargo",
            "test",
        ),
        (
            "go",
            "test",
        ),
    }

    if (
        tokens[0]
        in {
            "pytest",
            "tox",
        }
        or tuple(tokens[:2]) in test_prefixes
    ):
        return Classification(
            "test.run",
            None,
            "bash.test",
        )

    if tokens[0] in {
        "cat",
        "sed",
        "head",
        "tail",
    }:
        return Classification(
            "repository.read",
            None,
            "bash.read",
        )

    if tokens[0] in {
        "cd",
        "pwd",
        "ls",
        "find",
    }:
        return Classification(
            "repository.navigate",
            None,
            "bash.navigate",
        )

    return Classification(
        "command.execute",
        None,
        "bash.command",
    )


def classify_bash(
    command: Any,
) -> tuple[Classification, ...]:
    """Classify compound shell input without retaining source text."""

    if not isinstance(command, str) or not command:
        return (
            Classification(
                "command.execute.unknown",
                "sink:unclassified-command",
                "bash.malformed",
            ),
        )

    segments = _segments(command)

    if not segments:
        return (
            Classification(
                "command.execute.unknown",
                "sink:unclassified-command",
                "bash.unparsed",
            ),
        )

    result: list[Classification] = []

    for segment in segments:
        tokens = _unwrap(segment)

        classification = (
            _git(tokens)
            or _package_publish(tokens)
            or _sensitive(tokens)
            or _routine(tokens)
        )

        result.append(classification)

    return tuple(result)


def classify_tool(
    tool_name: str,
    tool_input: Mapping[str, Any],
) -> tuple[Classification, ...]:
    """Classify one tool request into normalized capabilities."""

    if tool_name == "Bash":
        return classify_bash(tool_input.get("command"))

    known = _TOOL_RULES.get(tool_name)

    if known is not None:
        return (known,)

    if tool_name.startswith("mcp__"):
        return (
            Classification(
                "mcp.invoke",
                None,
                "tool.mcp",
            ),
        )

    return (
        Classification(
            "tool.invoke.unknown",
            None,
            "tool.unknown",
        ),
    )
