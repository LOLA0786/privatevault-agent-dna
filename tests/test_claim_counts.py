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
# modules are not collected at all. A machine with the wheel can collect
# more tests than CI does. An exact-equality guard therefore cannot hold
# in both places -- it went red in CI the first time it ran.
#
# So the claim is a FLOOR. It may never overstate the evidence, and it may
# not drift so far below reality that it stops meaning anything.
STALENESS_TOLERANCE = 40

# A session collecting fewer than this is a subset, not the suite.
# The full suite is an order of magnitude larger.
PARTIAL_RUN_CEILING = 100


@pytest.fixture(scope="module")
def collected(request) -> int:
    """The number of tests THIS session collected.

    Deliberately not a nested `pytest --collect-only` subprocess. That
    was the first design and it was wrong: a subprocess collects in its
    own environment, which need not match the run that is executing this
    assertion, so the guard could fail in CI while passing locally with
    no way to see why. `session.testscollected` is the count of the run
    actually in progress, which is the only number this assertion has
    any business comparing against.
    """
    return int(request.session.testscollected)


@pytest.mark.parametrize("relpath", sorted(CLAIM_SITES))
def test_documented_test_count_matches_reality(relpath: str, collected: int) -> None:
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
    if collected < PARTIAL_RUN_CEILING:
        # A subset was selected (single file, -k, -x). The claim is about
        # the whole suite, so there is nothing to check. Deliberately an
        # ABSOLUTE floor rather than "collected < claimed": the latter
        # would silently skip whenever the claim was too high, which is
        # precisely the failure this guard exists to catch.
        pytest.skip(f"partial run: only {collected} tests collected")
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
