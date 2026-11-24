"""CONTRIBUTING.md lists the gates CI runs, so a change that passes locally
passes CI. (A local format check over fewer directories than CI's once let a
pull request through locally and fail in CI.)"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CI = ROOT / ".github" / "workflows" / "ci.yml"
GUIDE = ROOT / "CONTRIBUTING.md"


def _flat(text: str) -> str:
    return " ".join(text.replace("\\\n", " ").split())


def ci_gates(ci: dict) -> list[str]:
    """Every `uv run` command in the python job, negation stripped."""
    out = []
    for step in ci["jobs"]["python"]["steps"]:
        for line in str(step.get("run", "")).splitlines():
            line = line.strip().removeprefix("! ")
            if line.startswith("uv run "):
                out.append(" ".join(line.split()))
    return out


def missing_gates(ci: dict, guide: str) -> list[str]:
    flat = _flat(guide)
    return [gate for gate in ci_gates(ci) if gate not in flat]


def test_contributing_lists_every_ci_gate():
    ci = yaml.safe_load(CI.read_text(encoding="utf-8"))
    assert len(ci_gates(ci)) >= 8
    assert missing_gates(ci, GUIDE.read_text(encoding="utf-8")) == []


def test_negative_control_missing_gate_is_caught():
    ci = {"jobs": {"python": {"steps": [{"run": "uv run mypy a\n! uv run b x"}]}}}
    assert missing_gates(ci, "uv run mypy a") == ["uv run b x"]
