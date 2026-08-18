"""Stdio MCP upstream must not inherit the parent environment."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from agent_dna.gateway.credentials import (
    STDIO_ENV_ALLOWLIST,
    UpstreamCredentials,
)
from agent_dna.gateway.upstream import StdioUpstream

DECLARED = "declared-upstream-credential-value"


def _forbidden_name(name: str) -> bool:
    upper = name.upper()
    if upper.startswith(("PV_", "AWS_", "GOOGLE_", "ANTHROPIC_", "OPENAI_")):
        return True
    return upper.endswith("_KEY") or upper.endswith("_TOKEN")


def test_stdio_child_env_is_allowlist_only(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("PV_AGENT_API_KEY", "should-never-reach-child")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "aws-should-not-leak")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/tmp/adc.json")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-should-not-leak")
    monkeypatch.setenv("OPENAI_API_KEY", "openai-should-not-leak")
    monkeypatch.setenv("RANDOM_TOKEN", "token-should-not-leak")
    monkeypatch.setenv("RANDOM_KEY", "key-should-not-leak")

    dump = tmp_path / "child-env.json"
    script = (
        "import json, os, sys; "
        f"p = {str(dump)!r}; "
        "json.dump(dict(os.environ), open(p, 'w')); "
        "sys.stdout.write('ok')"
    )
    creds = UpstreamCredentials(env={"UPSTREAM_SECRET": DECLARED})
    upstream = StdioUpstream(
        command=[sys.executable, "-c", script],
        credentials=creds,
    )
    try:
        upstream.start()
        assert upstream._proc is not None
        upstream._proc.wait(timeout=10)
    finally:
        upstream.close()

    assert dump.is_file(), "child did not write its environment dump"
    child_env = json.loads(dump.read_text(encoding="utf-8"))

    assert "PV_AGENT_API_KEY" not in child_env
    assert child_env.get("UPSTREAM_SECRET") == DECLARED

    # CPython on macOS injects __CF_USER_TEXT_ENCODING into every child.
    # That is not copied from our env builder; it is still not a secret.
    runtime_injected = {"__CF_USER_TEXT_ENCODING"}
    allowed = set(STDIO_ENV_ALLOWLIST) | {"UPSTREAM_SECRET"} | runtime_injected
    extras = set(child_env) - allowed
    assert extras == set(), extras
    copied = set(child_env) - {"UPSTREAM_SECRET"} - runtime_injected
    assert copied <= STDIO_ENV_ALLOWLIST
    for name in copied:
        assert not _forbidden_name(name)
        assert child_env[name]
    for name in child_env:
        if name == "UPSTREAM_SECRET":
            continue
        assert not _forbidden_name(name)
