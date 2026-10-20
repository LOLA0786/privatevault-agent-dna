"""Dependabot keeps the pins current without breaking what must move together.

Lessons from the first run after #169 (PRs #170-#184): CodeQL's three steps
were bumped one at a time (a mixed v3/v4 run fails), react and react-dom
arrived separately (React refuses mismatched versions), and the pinned
Python base image was offered a 3.12 -> 3.14 interpreter jump.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CONFIG = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())


def _entry(ecosystem: str) -> dict:
    (entry,) = [u for u in CONFIG["updates"] if u["package-ecosystem"] == ecosystem]
    return entry


def test_codeql_steps_move_together():
    groups = _entry("github-actions")["groups"]
    # Dependabot names each step "github/codeql-action/<step>"; #187 moved
    # analyze alone under the single "github/codeql-action*" pattern.
    assert groups["codeql"]["patterns"] == [
        "github/codeql-action",
        "github/codeql-action/*",
    ]
    assert list(groups)[0] == "codeql"  # first match wins


def test_codeql_steps_share_one_commit():
    text = (ROOT / ".github" / "workflows" / "codeql.yml").read_text()
    pins = set(re.findall(r"github/codeql-action/\w+@([0-9a-f]{40})", text))
    assert len(pins) == 1, pins


def test_react_and_react_dom_move_together():
    groups = _entry("npm")["groups"]
    assert list(groups)[0] == "react"
    assert {"react", "react-dom"} <= set(groups["react"]["patterns"])


def test_python_base_image_gets_digests_not_version_jumps():
    docker = _entry("docker")
    ignored = {i["dependency-name"]: i["update-types"] for i in docker["ignore"]}
    assert set(ignored["python"]) == {
        "version-update:semver-major",
        "version-update:semver-minor",
    }
    root = Path(__file__).resolve().parents[1]
    dockerfiles = {
        "" if p.parent == root else p.parent.relative_to(root).as_posix()
        for p in root.rglob("Dockerfile")
        if not {".venv", "node_modules"} & set(p.parts)
    }
    covered = {d.strip("/") for d in docker["directories"]}
    assert dockerfiles <= covered, dockerfiles - covered
