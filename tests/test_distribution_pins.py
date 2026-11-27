"""Distributions depend on PrivateVault packages by URL and commit, never by bare name.

No privatevault-* name is published on PyPI. A bare pin such as
privatevault-agent-dna==0.3.0 can therefore only be satisfied by whoever
registers the name first: a dependency-confusion route to code execution
on install (audit finding, infra). Depend on this repository by URL,
pinned to a full 40-character commit, which nobody can move.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PINNED = re.compile(
    r"@\s*git\+https://github\.com/LOLA0786/privatevault-agent-dna@[0-9a-f]{40}$"
)


def test_privatevault_dependencies_are_pinned_by_url_to_a_commit():
    offenders = []
    for pyproject in sorted(ROOT.glob("distributions/*/pyproject.toml")):
        project = tomllib.loads(pyproject.read_text(encoding="utf-8")).get(
            "project", {}
        )
        for dependency in project.get("dependencies", []):
            if re.match(
                r"\s*privatevault[-_]", dependency, re.IGNORECASE
            ) and not PINNED.search(dependency.strip()):
                offenders.append(f"{pyproject.relative_to(ROOT)}: {dependency}")
    assert not offenders, (
        "bare PrivateVault pins resolve from PyPI, where the names are unclaimed:\n"
        + "\n".join(offenders)
    )
