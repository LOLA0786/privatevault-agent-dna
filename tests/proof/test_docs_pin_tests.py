"""P5 and P6: the threat model and the evaluation guide cite real tests.

Every ``tests/<file>.py::<test_name>`` reference in docs/THREAT-MODEL.md and
docs/EVALUATE.md must name a test function that exists, and every
``proof/...`` or ``agents/...`` path they cite must exist. A doc that cites
a test that was renamed or deleted fails here, so the tables cannot go
stale.

Claims -> tests:
  - Every cited test exists
    -> test_every_cited_test_exists
  - Every cited path exists
    -> test_every_cited_path_exists
  - The threat model has the required sections and lists non-goals
    -> test_threat_model_shape
  - The evaluation guide has success criteria and a mermaid diagram
    -> test_evaluate_shape
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
DOCS = [REPO / "docs" / "THREAT-MODEL.md", REPO / "docs" / "EVALUATE.md"]

TEST_REF = re.compile(r"`(tests/[\w/.-]+\.py)::(test_\w+)`")
PATH_REF = re.compile(r"`((?:proof|agents|network|tools|docs)/[\w/.-]+)`")


def _text(path: Path) -> str:
    assert path.exists(), f"{path} is missing"
    return path.read_text(encoding="utf-8")


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_every_cited_test_exists(doc):
    text = _text(doc)
    refs = TEST_REF.findall(text)
    assert refs, f"{doc.name} cites no tests"
    for file, name in refs:
        source = REPO / file
        assert source.exists(), f"{doc.name}: {file} does not exist"
        assert re.search(rf"^(?:async )?def {name}\(", source.read_text(), re.M), (
            f"{doc.name}: {file}::{name} does not exist"
        )


@pytest.mark.parametrize("doc", DOCS, ids=lambda p: p.name)
def test_every_cited_path_exists(doc):
    text = _text(doc)
    for ref in PATH_REF.findall(text):
        assert (REPO / ref).exists(), f"{doc.name}: {ref} does not exist"


def test_threat_model_shape():
    text = _text(DOCS[0])
    for heading in ("## Attacks", "## Non-goals", "## Evidence"):
        assert heading in text, heading
    # One row per attack with a control and a pinning test.
    rows = [
        line for line in text.splitlines() if line.startswith("| ") and "tests/" in line
    ]
    assert len(rows) >= 8
    assert "—" not in text


def test_evaluate_shape():
    text = _text(DOCS[1])
    assert "```mermaid" in text
    assert "## Success criteria" in text
    assert "docker compose -f proof/docker-compose.yml up" in text
    assert "—" not in text
