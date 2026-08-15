"""Pilot tests must not execute without -m pilot and a valid seed-state.

Lives under tests/pilot/ so it is deleted with the experiment. Do not
put these assertions in tests/test_pilot_isolation.py — that file must
survive `rm -rf pilot/ tests/pilot/ docs/pilot/`.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from tests.pilot.conftest import require_seed_state

pytestmark = pytest.mark.pilot

_REPO = Path(__file__).resolve().parents[2]


def _pytest_pilot_dir(
    *, extra_env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("FINERACT_PILOT", None)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/pilot",
            "-q",
            "--tb=no",
        ],
        cwd=_REPO,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def _passed_count(output: str) -> int:
    match = re.search(r"(\d+) passed", output)
    return int(match.group(1)) if match else 0


def test_plain_pytest_does_not_execute_pilot_tests() -> None:
    """Live lab tests must not run without pytest -m pilot."""
    proc = _pytest_pilot_dir()
    output = proc.stdout + proc.stderr
    assert _passed_count(output) == 0, output
    assert proc.returncode == 0, output


def test_fineract_pilot_env_does_not_bypass_marker() -> None:
    """FINERACT_PILOT=1 is not an opt-in; only -m pilot is."""
    proc = _pytest_pilot_dir(extra_env={"FINERACT_PILOT": "1"})
    output = proc.stdout + proc.stderr
    assert _passed_count(output) == 0, output
    assert proc.returncode == 0, output


def test_path_selected_pilot_test_does_not_execute_unmarked() -> None:
    env = os.environ.copy()
    env.pop("FINERACT_PILOT", None)
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/pilot/test_fineract_enforcement.py::test_budget_exhausted_across_agents",
            "-q",
            "--tb=no",
        ],
        cwd=_REPO,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    output = proc.stdout + proc.stderr
    assert _passed_count(output) == 0, output
    assert "skipped" in output.lower(), output


def test_pilot_setup_requires_seed_state(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "tests.pilot.conftest._SEED_STATE", tmp_path / "missing-seed-state.json"
    )
    with pytest.raises(RuntimeError, match="seed-state"):
        require_seed_state()
