"""Compliance and readiness documents may only cite files that exist.

A control mapping that points at a missing module is worse than none: an
auditor follows the path and finds nothing (2026-10-19: the SOC 2 mapping
cited ``agent_dna/auth/`` and ``agent_dna/audit/``, which do not exist).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCS = sorted(
    [*ROOT.glob("docs/compliance/**/*.md"), ROOT / "docs" / "ENTERPRISE-READINESS.md"]
)
TOP = (
    "agent_dna/",
    "api/",
    "tools/",
    "tests/",
    "docs/",
    "deploy/",
    "rust/",
    ".github/",
    "spec/",
    "examples/",
)
PATH = re.compile(r"`([^`\s]+)`")


def _cited(doc: Path) -> list[str]:
    out = []
    for raw in PATH.findall(doc.read_text(encoding="utf-8")):
        p = raw.split("::", 1)[0]
        if p.startswith(TOP) or p in {
            "uv.lock",
            "Dockerfile",
            "CHANGELOG.md",
            "SECURITY.md",
        }:
            out.append(p)
    return out


@pytest.mark.parametrize("doc", DOCS, ids=lambda d: str(d.relative_to(ROOT)))
def test_every_cited_path_exists(doc):
    missing = [p for p in _cited(doc) if not (ROOT / p).exists()]
    assert not missing, f"{doc.relative_to(ROOT)} cites missing paths: {missing}"


def test_readiness_doc_is_checked():
    assert (ROOT / "docs" / "ENTERPRISE-READINESS.md") in DOCS
    assert len(_cited(ROOT / "docs" / "ENTERPRISE-READINESS.md")) > 20
