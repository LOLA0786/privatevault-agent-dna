"""pv up writes Claude Code sandbox settings; pv claude starts Claude Code
with them (ADR 0034).

Claims -> tests:
  - The settings sandbox every Bash command, refuse to run unsandboxed, and
    deny reading PrivateVault's state and the usual credential places, and
    writing the state -> test_settings_shape
  - The file is owner-only and refreshed on every start -> test_written_by_pv_up
  - pv claude runs `claude --settings <file> ...` and refuses when the
    sandbox's Linux requirements or claude are missing -> test_pv_claude_*
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from agent_dna.cli import main as pv
from agent_dna.quickstart import sandbox
from agent_dna.quickstart.sandbox import SETTINGS_NAME, claude_settings


def test_settings_shape(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    s = claude_settings(tmp_path, project)["sandbox"]
    assert s["enabled"] is True
    assert s["failIfUnavailable"] is True
    assert s["allowUnsandboxedCommands"] is False
    deny_read = s["filesystem"]["denyRead"]
    for place in (str(tmp_path), "~/.privatevault", "~/.ssh", "~/.aws"):
        assert place in deny_read
    # project patterns are absolute: a relative glob is resolved from the
    # settings file's folder, which left the project's .env readable
    assert f"{project.resolve()}/**/.env" in deny_read
    assert f"{project.resolve()}/**/.env.*" in deny_read
    assert not [p for p in deny_read if p.startswith("**")]
    assert str(tmp_path) in s["filesystem"]["denyWrite"]


def test_written_by_pv_up(tmp_path):
    home = tmp_path / "pv"
    project = tmp_path
    assert (
        pv(["up", "--home", str(home), "--workdir", str(project), "--print-env"]) == 0
    )
    path = home / SETTINGS_NAME
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text()) == claude_settings(home.resolve(), project)
    path.write_text("{}")
    path.chmod(0o600)
    assert (
        pv(["up", "--home", str(home), "--workdir", str(project), "--print-env"]) == 0
    )
    assert json.loads(path.read_text()) == claude_settings(home.resolve(), project)


def test_pv_claude_execs_with_settings(tmp_path, monkeypatch):
    seen: list = []
    monkeypatch.setattr(sandbox, "missing_requirements", lambda: [])
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr(sandbox.os, "execv", lambda exe, argv: seen.append(argv))
    home = tmp_path / "pv"
    monkeypatch.chdir(tmp_path)
    assert pv(["claude", "--home", str(home), "--", "-p", "hello"]) == 0
    ((argv),) = seen
    assert argv[:2] == ["/usr/bin/claude", "--settings"]
    assert Path(argv[2]) == home.resolve() / SETTINGS_NAME
    assert argv[3:] == ["-p", "hello"]
    written = json.loads(Path(argv[2]).read_text())["sandbox"]["filesystem"]
    assert f"{tmp_path.resolve()}/**/.env" in written["denyRead"]  # for this project


def test_pv_claude_needs_the_sandbox_tools(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sandbox, "missing_requirements", lambda: ["bwrap", "socat"])
    assert pv(["claude", "--home", str(tmp_path / "pv")]) == 2
    assert "bwrap and socat" in capsys.readouterr().err


def test_pv_claude_needs_claude(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sandbox, "missing_requirements", lambda: [])
    monkeypatch.setattr(sandbox.shutil, "which", lambda name: None)
    assert pv(["claude", "--home", str(tmp_path / "pv")]) == 2
    assert "not on PATH" in capsys.readouterr().err


@pytest.mark.parametrize("system,expected", [("Darwin", []), ("Windows", [])])
def test_requirements_are_linux_only(monkeypatch, system, expected):
    monkeypatch.setattr(sandbox.platform, "system", lambda: system)
    assert sandbox.missing_requirements() == expected
