"""The money-path attack corpus runs clean (demos/live_checkout/attacks.py).

Claims -> tests:
  - Every attack in the corpus moves no money it should not: a changed
    amount, a replayed permit, one permit presented concurrently, one
    decision minted many times, one approval used twice, one refund decided
    twice (server reservation, ADR 0041; receiver key alone, ADR 0040)
    -> test_corpus_passes
  - The destination ledger matches the gate's signed receipts one for one,
    and the receipts verify and fail after a byte is changed
    -> test_corpus_passes
  - Posting straight to the mock upstream is NOT prevented, and shows up as
    a payment with no admitted receipt
    -> test_corpus_passes
  - The command exits 0 and prints one line per scenario
    -> test_command_line
"""

from __future__ import annotations

import pytest

from demos.live_checkout import attacks


@pytest.fixture(scope="module")
def report(tmp_path_factory):
    return attacks.run(tmp_path_factory.mktemp("attacks"))


def test_corpus_passes(report):
    by_name = {o["name"]: o for o in report["outcomes"]}
    expected = [s.__name__ for s, _ in attacks.SCENARIOS + attacks.RECEIVER_ALONE]
    assert len(expected) == 8
    for name in expected:
        assert by_name[name]["status"] == attacks.PASS, by_name[name]
    assert report["failed"] == []

    bypass = by_name["upstream_reached_without_the_gate"]
    assert bypass["status"] == attacks.NOT_PREVENTED
    assert "no admitted receipt" in bypass["detail"]

    reconciliation = report["reconciliation_before_limits"]
    assert reconciliation["ok"]
    assert reconciliation["payments"] == reconciliation["admitted_receipts"] == 7
    assert report["receipts"]["ok"]
    # Nothing in the ledger but the seven honest refunds and the bypass.
    amounts = sorted(int(r["amount"]) for r in report["destination_ledger"])
    assert amounts == [850, 1200, 1999, 2400, 3000, 3000, 25000, 30000]
    assert any("EXECUTED" in note for note in report["observations"])


def test_command_line(tmp_path, capsys):
    assert attacks.main(["--run-dir", str(tmp_path / "run")]) == 0
    out = capsys.readouterr().out
    assert out.count("[PASS]") == 10 and "[FAIL]" not in out
    assert "[NOT PREVENTED] upstream_reached_without_the_gate" in out
    assert (tmp_path / "run" / "attacks.json").exists()
