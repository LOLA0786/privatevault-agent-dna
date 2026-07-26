"""Documented test counts must equal the real one.

The repository's position is that every claim is checkable. The test
count is the most-repeated claim in the project and it is currently the
least checked: at the time this guard was written the README said 452,
WHAT-WE-DO-NOT-CLAIM.md said 561, the flagship demo printed 286, and the
suite actually collected far more. Four numbers, none matching, in the
documents whose whole purpose is that the numbers can be trusted.

Nobody wrote a wrong number on purpose. They drifted because the count
lives in prose and prose has no build step. This test gives it one.

When you add or remove tests this will fail. That is the intended
behaviour: updating the claim is part of the change that invalidated it,
exactly as WHAT-WE-DO-NOT-CLAIM.md is updated in the same commit as the
code it describes. The fix is to run

    python -m pytest --collect-only -q | tail -1

and put that number in the places listed in CLAIM_SITES below.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

# Every file that states a test count, and the pattern that finds it.
# Add a site here rather than letting a fifth number appear somewhere.
CLAIM_SITES: dict[str, re.Pattern[str]] = {
    "README.md": re.compile(r"python -m pytest -q\s+#\s*(\d+)\+?\s+tests"),
    "docs/WHAT-WE-DO-NOT-CLAIM.md": re.compile(
        r"(\d+)\+?\s+automated tests, run in CI"
    ),
    "examples/composed_line_demo.py": re.compile(
        r"every level is a tested code path, (\d+)\+? automated tests"
    ),
}

# The collected count is ENVIRONMENT-DEPENDENT: tests/test_rust_*.py use
# pytest.importorskip at module level, so without the Rust wheel those
# modules are not collected at all. A machine with the wheel collects six
# more tests than CI does. An exact-equality guard therefore cannot hold
# in both places -- it went red in CI the first time it ran.
#
# So the claim is a FLOOR. It may never overstate the evidence, and it may
# not drift so far below reality that it stops meaning anything.
STALENESS_TOLERANCE = 40


def _collected_count() -> int:
    """Ask pytest itself. Deliberately a subprocess against the real
    testpaths -- an in-process count would have to reimplement
    collection and would drift from what CI actually runs."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q",
         "-p", "no:cacheprovider"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        timeout=300,
    )
    m = re.search(r"(\d+) tests? collected", proc.stdout)
    assert m is not None, (
        "could not parse pytest collection output:\n"
        f"{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}"
    )
    return int(m.group(1))


@pytest.fixture(scope="module")
def collected() -> int:
    return _collected_count()


@pytest.mark.parametrize("relpath", sorted(CLAIM_SITES))
def test_documented_test_count_matches_reality(
    relpath: str, collected: int
) -> None:
    path = REPO_ROOT / relpath
    assert path.exists(), f"claim site {relpath} no longer exists"

    pattern = CLAIM_SITES[relpath]
    text = path.read_text(encoding="utf-8")
    found = pattern.findall(text)

    assert found, (
        f"{relpath} no longer states a test count in the expected form "
        f"({pattern.pattern!r}). Either the claim was removed -- in which "
        f"case drop it from CLAIM_SITES -- or it was reworded, in which "
        f"case this guard stopped guarding anything."
    )
    assert len(found) == 1, (
        f"{relpath} states the test count {len(found)} times ({found}); "
        f"keep it to one so there is one thing to update"
    )

    claimed = int(found[0])
    assert claimed <= collected, (
        f"{relpath} claims {claimed} tests; the suite collects only "
        f"{collected}. The claim overstates the evidence, which is the "
        f"one direction that is never acceptable."
    )
    assert collected - claimed <= STALENESS_TOLERANCE, (
        f"{relpath} claims {claimed} tests; the suite collects "
        f"{collected}, which is {collected - claimed} more. The claim has "
        f"gone stale -- update it to {collected}."
    )


def test_all_claim_sites_agree_with_each_other() -> None:
    """Cheap cross-check that runs without invoking pytest again: even
    if collection changed, the documents must not disagree among
    themselves."""
    numbers: dict[str, int] = {}
    for relpath, pattern in CLAIM_SITES.items():
        found = pattern.findall((REPO_ROOT / relpath).read_text(encoding="utf-8"))
        if found:
            numbers[relpath] = int(found[0])

    distinct = set(numbers.values())
    assert len(distinct) <= 1, (
        "documented test counts disagree with each other: "
        + ", ".join(f"{k} says {v}" for k, v in sorted(numbers.items()))
    )
