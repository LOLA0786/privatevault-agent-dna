"""The flagship demo must demonstrate what it says it demonstrates.

examples/composed_line_demo.py is the first artifact the README tells a
reader to run, and it prints a summary table mapping each precedence
level to the trigger that fired. That table is a public claim.

It has silently broken before. Raising the demo breaker's cumulative cap
without re-checking the scenarios caused the L3 wire (900,000) to trip
the breaker mid-walk; every scenario after it then reported
`circuit_breaker` instead of its own level, and the treasury drain that
was calibrated against a $1,000 cap stopped tripping at all. The engine
was correct throughout -- the demo was not.

This test pins the mapping. A scenario labelled "capability grant" must
be refused BY authorization, not by something upstream that happens to
fire first. If a future change to the demo, the breaker, or the
precedence order breaks that correspondence, this fails rather than
shipping a table that contradicts itself.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO = REPO_ROOT / "examples" / "composed_line_demo.py"

# label fragment -> the triggered_by that label promises
EXPECTED_TRIGGER = {
    "L0  enterprise constraint": "uaal_constraint",
    "L1  behavioral invariant": "invariant",
    "L2  multi-agent consensus": "consensus",
    "L3  capability grant": "authorization",
    "L4  economics": "economics",
    "L5  learned drift": "drift",
    "L6  baseline": "baseline",
    "L-1 circuit breaker": "circuit_breaker",
}

SUMMARY_ROW = re.compile(
    r"^(?P<label>L(?:-1|\d)\s+\S.*?)\s{2,}"
    r"(?P<verdict>ALLOW|BLOCK|REQUIRE_APPROVAL)\s+"
    r"(?P<trigger>\S+)\s+"
    r"(?P<signed>[YN])\s*$"
)


@pytest.fixture(scope="module")
def demo_output(tmp_path_factory) -> str:
    """Run the demo once, in a throwaway cwd so its SQLite artifacts
    (decision log, breaker DBs) never touch the working tree."""
    workdir = tmp_path_factory.mktemp("composed_line_demo")
    proc = subprocess.run(
        [sys.executable, str(DEMO)],
        capture_output=True,
        text=True,
        cwd=workdir,
        timeout=300,
    )
    assert proc.returncode == 0, (
        f"demo exited {proc.returncode}\n"
        f"--- stdout ---\n{proc.stdout[-4000:]}\n"
        f"--- stderr ---\n{proc.stderr[-4000:]}"
    )
    return proc.stdout


def _summary_rows(output: str) -> dict[str, dict[str, str]]:
    rows: dict[str, dict[str, str]] = {}
    for line in output.splitlines():
        m = SUMMARY_ROW.match(line.rstrip())
        if m is None:
            continue
        rows[m.group("label").strip()] = {
            "verdict": m.group("verdict"),
            "trigger": m.group("trigger"),
            "signed": m.group("signed"),
        }
    return rows


def test_demo_summary_table_is_present(demo_output: str) -> None:
    rows = _summary_rows(demo_output)
    assert len(rows) == len(EXPECTED_TRIGGER), (
        f"expected {len(EXPECTED_TRIGGER)} summary rows, parsed {len(rows)}: "
        f"{sorted(rows)}"
    )


@pytest.mark.parametrize(("label", "expected"), sorted(EXPECTED_TRIGGER.items()))
def test_each_level_is_refused_by_its_own_level(
    demo_output: str, label: str, expected: str
) -> None:
    """The whole point of the ladder: the level a scenario is written to
    exercise is the level that must fire. Anything else means an
    upstream level pre-empted it and the label is a lie."""
    rows = _summary_rows(demo_output)
    matches = [k for k in rows if k.startswith(label)]
    assert matches, f"no summary row for {label!r}; parsed {sorted(rows)}"
    actual = rows[matches[0]]["trigger"]
    assert actual == expected, (
        f"scenario {label!r} claims to demonstrate {expected!r} "
        f"but was refused by {actual!r} -- an upstream level pre-empted it, "
        f"so the printed table contradicts the precedence claim"
    )


def test_every_demo_record_is_signed(demo_output: str) -> None:
    rows = _summary_rows(demo_output)
    unsigned = [k for k, v in rows.items() if v["signed"] != "Y"]
    assert not unsigned, f"unsigned decision records in the demo: {unsigned}"


def test_baseline_is_the_only_allow(demo_output: str) -> None:
    """L6 is the control: an in-profile action with nothing to trip on.
    If it stops being ALLOW, the demo no longer shows that the runtime
    permits normal work -- it just shows a system that blocks."""
    rows = _summary_rows(demo_output)
    allowed = [k for k, v in rows.items() if v["verdict"] == "ALLOW"]
    assert allowed == [k for k in rows if k.startswith("L6  baseline")], (
        f"expected exactly L6 to be ALLOW, got {allowed}"
    )


def test_demo_chain_verifies_under_the_independent_verifier(
    demo_output: str,
) -> None:
    """The demo shells out to tools/verify_records.py. That verdict is
    the demo's strongest claim; assert it rather than trust it."""
    assert "independent verifier     : VERDICT: PASS" in demo_output, (
        "the demo's own independent verification did not pass"
    )
    assert "enforcement divergences  : 0" in demo_output


def test_breaker_narration_matches_the_configured_cap(
    demo_output: str,
) -> None:
    """The L-1 section prints a cumulative total against a cap. Those two
    numbers come from different places (narration string vs BreakerConfig)
    and have drifted apart before."""
    m = re.search(
        r"cumulative \$([\d,]+) > \$([\d,]+) window cap -> BREAKER TRIPPED",
        demo_output,
    )
    assert m is not None, "L-1 section never reported a breaker trip"
    reached = int(m.group(1).replace(",", ""))
    cap = int(m.group(2).replace(",", ""))
    assert reached > cap, f"narration claims a trip at {reached} against cap {cap}"
    assert f"cap {cap}.00" in demo_output, (
        "the narrated cap does not match the cap the breaker actually "
        "enforced in its refusal reason"
    )
