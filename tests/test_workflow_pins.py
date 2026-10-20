"""Every GitHub Action the workflows run is pinned to a full commit SHA.

A tag such as ``@v7`` or a branch such as ``@stable`` can be moved by whoever
controls that repository, and the next CI run (including the release job,
which holds ``id-token: write`` and ``packages: write``) would execute the new
code. A 40-character commit SHA cannot be moved. Each pin carries the
version it was taken from as a comment, which Dependabot (``github-actions``
ecosystem) keeps current.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

WORKFLOWS = sorted(
    (Path(__file__).resolve().parents[1] / ".github" / "workflows").glob("*.y*ml")
)
USES = re.compile(r"^\s*-?\s*uses:\s*(\S+)(.*)$")
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


def _uses(path: Path) -> list[tuple[int, str, str]]:
    out = []
    for n, line in enumerate(path.read_text().splitlines(), 1):
        m = USES.match(line)
        if m:
            out.append((n, m.group(1), m.group(2)))
    return out


def test_there_are_workflows_to_check():
    assert WORKFLOWS
    assert sum(len(_uses(p)) for p in WORKFLOWS) >= 30


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_every_action_is_pinned_to_a_commit(path):
    yaml.safe_load(path.read_text())  # still valid YAML
    for line, ref, rest in _uses(path):
        if ref.startswith("./") or ref.startswith("docker://"):
            continue
        assert PINNED.match(ref), f"{path.name}:{line}: {ref} is not pinned to a SHA"
        assert rest.strip().startswith("#") and len(rest.strip()) > 1, (
            f"{path.name}:{line}: say which version {ref} is (# vX.Y.Z)"
        )
