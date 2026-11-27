"""The policy-gate workflow fails closed when it cannot see what changed.

.github/workflows/policy-gate.yml is a template customers copy into their
policy repositories. Its gate step diffed against the base branch under
`set +e` on a depth-1 checkout: the diff failed for want of a merge base,
no rule file was listed, nothing was checked, and the gate passed (audit
finding, infra). These tests run the step's own script in real git
repositories, with a stand-in `pv` on PATH.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "policy-gate.yml"


def _steps() -> list[dict]:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["gate"]["steps"]


def _gate_script(text: str | None = None) -> str:
    steps = yaml.safe_load(text)["jobs"]["gate"]["steps"] if text else _steps()
    return next(step for step in steps if step.get("id") == "gate")["run"]


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


@pytest.fixture
def origin(tmp_path: Path) -> Path:
    """A repository whose `pr` branch tightens one policy rule."""
    repo = tmp_path / "origin"
    (repo / "policies").mkdir(parents=True)
    _git(repo, "init", "-q", "-b", "master")
    _git(repo, "config", "user.email", "gate@example.test")
    _git(repo, "config", "user.name", "gate")
    (repo / "policies" / "wire.json").write_text('{"limit": 100}\n')
    (repo / "policies" / "corpus.jsonl").write_text("{}\n")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "base")
    _git(repo, "checkout", "-qb", "pr")
    (repo / "policies" / "wire.json").write_text('{"limit": 50}\n')
    _git(repo, "commit", "-qam", "tighten the wire limit")
    return repo


def _clone(origin: Path, dest: Path, *, shallow: bool) -> Path:
    depth = ["--depth", "1"] if shallow else []  # depth 1 is actions/checkout's default
    _git(
        dest.parent,
        "clone",
        "-q",
        "--branch",
        "pr",
        *depth,
        f"file://{origin}",
        dest.name,
    )
    return dest


def _run_gate(
    repo: Path, tmp_path: Path, script: str, *, pv_exit: int = 0
) -> tuple[str, str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    pv = bin_dir / "pv"
    pv.write_text(f'#!/bin/sh\necho "checked $*"\nexit {pv_exit}\n')
    pv.chmod(0o755)
    output = tmp_path / "github_output"
    output.write_text("")
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "BASE_REF": "master",
        "MAX_NEW_BLOCKS": "0",
        "GITHUB_OUTPUT": str(output),
    }
    subprocess.run(
        ["bash", "-c", script],
        cwd=repo,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    status = dict(line.split("=", 1) for line in output.read_text().splitlines())[
        "status"
    ]
    return status, (repo / "gate_report.md").read_text()


def test_the_checkout_fetches_the_history_the_diff_needs():
    checkout = next(
        step
        for step in _steps()
        if str(step.get("uses", "")).startswith("actions/checkout@")
    )
    assert (checkout.get("with") or {}).get("fetch-depth") == 0


def test_a_shallow_clone_fails_the_gate_instead_of_passing_it(origin, tmp_path):
    repo = _clone(origin, tmp_path / "shallow", shallow=True)
    status, report = _run_gate(repo, tmp_path, _gate_script())
    assert status == "1"
    assert "could not diff" in report


def test_a_full_clone_checks_the_changed_rule(origin, tmp_path):
    repo = _clone(origin, tmp_path / "full", shallow=False)
    status, report = _run_gate(repo, tmp_path, _gate_script())
    assert status == "0"
    assert "checked policy check --rule policies/wire.json" in report


def test_a_failing_rule_fails_the_gate(origin, tmp_path):
    repo = _clone(origin, tmp_path / "full", shallow=False)
    status, _ = _run_gate(repo, tmp_path, _gate_script(), pv_exit=3)
    assert status == "3"


def test_the_base_branch_is_never_interpolated_into_the_script():
    assert "${{" not in _gate_script()
