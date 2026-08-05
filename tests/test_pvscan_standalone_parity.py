"""The two shipped pvscan copies must match each other and their generator.

`tools/build_pvscan_standalone.py` flattens agent_dna/scan/* into a single
file, written to both distributions/pvscan.py and distributions/pvscan-kit/.
Between 2026-08-01 and 2026-08-04 the builder wrote only the first path and
the committed artifact fell 118 lines behind its sources, shipping a pvscan
with no ADR extractor and no MCP manifest. This test closes that window.

Comparison is on the body only: the header carries a commit hash and a build
date, so a byte comparison would fail on every rebuild rather than on drift.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "tools" / "build_pvscan_standalone.py"
COPIES = (
    ROOT / "distributions" / "pvscan.py",
    ROOT / "distributions" / "pvscan-kit" / "pvscan.py",
)

_SECTION = re.compile(r"^# ={60,}$", re.MULTILINE)


def _body(text: str) -> str:
    """Everything from the first generated section marker onward."""
    match = _SECTION.search(text)
    assert match is not None, "no generated section marker found"
    return text[match.start():]


def test_both_shipped_copies_are_identical() -> None:
    first, second = (_body(p.read_text(encoding="utf-8")) for p in COPIES)
    assert first == second, "the two committed pvscan copies have diverged"


def _builder():
    spec = importlib.util.spec_from_file_location("_pvscan_builder", BUILDER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_committed_copy_matches_a_fresh_build(tmp_path: Path) -> None:
    """Rebuild from the working tree into a temp path; never mutate the repo.

    Reuses the builder's own _emit so the ruff passes are the real ones
    rather than a reimplementation that could drift from them.
    """
    builder = _builder()
    fresh = tmp_path / "pvscan.py"
    builder._emit(fresh, builder.build())
    expected = _body(fresh.read_text(encoding="utf-8"))

    for committed in COPIES:
        assert _body(committed.read_text(encoding="utf-8")) == expected, (
            f"{committed.relative_to(ROOT)} is stale relative to agent_dna/scan"
        )
