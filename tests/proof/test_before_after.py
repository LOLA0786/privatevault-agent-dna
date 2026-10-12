"""P2: finance ops with PrivateVault off, then on.

Before: the same agent code path minus the gate. The agent holds valid
credentials and posts its bytes to the payments upstream directly. The
amount changed after approval lands: the upstream shows 48,000.

After: the agents harness (decide, approval, permit, sidecar, receiver
gate). The same change is refused by the sidecar before any byte and by
the receiver when the sidecar is bypassed; the upstream shows only the
approved 18,000.

Claims -> tests:
  - Before: money moves; the upstream received amount 48,000; no decision
    record exists anywhere
    -> test_before_money_moves
  - After: refused twice; the upstream saw only 18,000
    -> test_after_is_refused_and_upstream_sees_only_the_approved_amount
  - The runner prints both blocks and exits 0
    -> test_run_prints_before_and_after
"""

from __future__ import annotations

from proof.before_after import run


def test_before_money_moves(tmp_path):
    result = run.before(tmp_path / "before")
    assert result.privatevault is False
    assert result.upstream_amounts == [48000]
    assert result.decision_records == 0
    assert result.http_status == 200


def test_after_is_refused_and_upstream_sees_only_the_approved_amount(tmp_path):
    result = run.after(tmp_path / "after")
    assert result.privatevault is True
    assert result.sidecar_reason == "EXECUTION_AUTHORIZATION_NON_CONFORMANT"
    assert result.receiver_status == 403
    assert result.receiver_reason == "RECEIVER_WIRE_MISMATCH"
    assert result.upstream_amounts == [18000]
    assert result.decision_records >= 2


def test_run_prints_before_and_after(capsys, tmp_path):
    assert run.main(["--run-dir", str(tmp_path / "run")]) == 0
    out = capsys.readouterr().out
    assert "BEFORE" in out and "AFTER" in out
    assert "48,000" in out and "RECEIVER_WIRE_MISMATCH" in out
    assert "PROOF HOLDS" in out
