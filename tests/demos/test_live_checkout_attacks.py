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
  - A request the sidecar delivered and the receiver refused is not recorded
    as paid: the sidecar's EXECUTED outcome means delivered, not admitted
    -> test_receiver_refusal_reads_the_receivers_answer[*],
       test_delivered_and_refused_is_not_recorded_as_paid
  - A request that was sent and paid but whose answer was lost (timeout) is
    recorded as outcome unknown: not paid, not prevented, excluded from the
    "prevented" headline, and the model is told not to retry
    -> test_corpus_passes (response_lost_after_payment),
       test_unknown_outcome_is_not_counted_as_prevented
"""

from __future__ import annotations

import pytest

from agents.core.gate import wire_for
from agents.core.transport import receiver_refusal
from demos.live_checkout import attacks
from demos.live_checkout.agent import Row


@pytest.fixture(scope="module")
def report(tmp_path_factory):
    return attacks.run(tmp_path_factory.mktemp("attacks"))


def test_corpus_passes(report):
    by_name = {o["name"]: o for o in report["outcomes"]}
    expected = [s.__name__ for s, _ in attacks.SCENARIOS + attacks.RECEIVER_ALONE]
    assert len(expected) == 9
    for name in expected:
        assert by_name[name]["status"] == attacks.PASS, by_name[name]
    assert report["failed"] == []

    bypass = by_name["upstream_reached_without_the_gate"]
    assert bypass["status"] == attacks.NOT_PREVENTED
    assert "no admitted receipt" in bypass["detail"]

    reconciliation = report["reconciliation_before_limits"]
    assert reconciliation["ok"]
    assert reconciliation["payments"] == reconciliation["admitted_receipts"] == 8
    assert report["receipts"]["ok"]
    # Nothing in the ledger but the seven honest refunds and the bypass.
    amounts = sorted(int(r["amount"]) for r in report["destination_ledger"])
    assert amounts == [850, 1200, 1999, 2400, 3000, 3000, 5000, 25000, 30000]
    assert any("EXECUTED" in note for note in report["observations"])


def test_command_line(tmp_path, capsys):
    assert attacks.main(["--run-dir", str(tmp_path / "run")]) == 0
    out = capsys.readouterr().out
    assert out.count("[PASS]") == 11 and "[FAIL]" not in out
    assert "[NOT PREVENTED] upstream_reached_without_the_gate" in out
    assert (tmp_path / "run" / "attacks.json").exists()


class _Transport:
    def __init__(self, status):
        self.last_response_status = status


@pytest.mark.parametrize(
    "status, body, expected",
    [
        (201, b'{"payout_ref": "P1"}', None),
        (399, b"", None),
        (None, b'{"reason_code": "X"}', None),
        (
            409,
            b'{"admitted": false, "reason_code": "RECEIVER_PERMIT_CONSUMED"}',
            (409, "RECEIVER_PERMIT_CONSUMED"),
        ),
        (403, b"not json", (403, None)),
        (500, None, (500, None)),
        (400, b'["reason_code"]', (400, None)),
        (400, b'{"reason_code": 7}', (400, None)),
    ],
    ids=[
        "created",
        "below-400",
        "no-status",
        "refused",
        "not-json",
        "no-body",
        "not-an-object",
        "non-string-reason",
    ],
)
def test_receiver_refusal_reads_the_receivers_answer(status, body, expected):
    assert receiver_refusal(_Transport(status), body) == expected
    assert receiver_refusal(object(), body) is None


def test_delivered_and_refused_is_not_recorded_as_paid(tmp_path, monkeypatch):
    """Found by the attack corpus. The permit is presented to the gate by
    someone else between mint and dispatch. The sidecar then delivers the
    honest bytes, the gate answers 409, and the sidecar's outcome is still
    EXECUTED. The demo recorded that row as paid and told the model so."""
    w = attacks.start_world(tmp_path / "run")
    try:
        path = w.p
        mint = path.pv.mint

        def mint_then_lose_the_race(outcome, tool, arguments):
            permit = mint(outcome, tool, arguments)
            assert w.present(permit, wire_for(arguments))[0] == 201
            return permit

        monkeypatch.setattr(path.pv, "mint", mint_then_lose_the_race)
        row = Row(
            id=1,
            kind="normal",
            order_id="ORD-70288",
            customer_id="C-1005",
            requested_amount=1999,
            requested_payee="meera.k@paytm",
            customer_text="refund please",
        )
        said = path.issue(
            row,
            {
                "order_id": "ORD-70288",
                "amount": 1999,
                "payee": "meera.k@paytm",
                "reason": "returned",
            },
            compromised=False,
            bypass_sidecar=False,
        )
        assert row.sidecar_outcome == "EXECUTED"  # delivered
        assert row.gate_status == 409  # and refused
        assert row.gate_reason in {
            "RECEIVER_DUPLICATE_TRANSACTION",
            "RECEIVER_PERMIT_CONSUMED",
        }
        assert not row.paid and row.payout_ref is None
        assert "NOT paid" in said and "Refund paid" not in said
        # Paid once, by the presentation that won.
        assert w.paid("ORD-70288") == [1999]
    finally:
        attacks.stop_world(w)


def test_unknown_outcome_is_not_counted_as_prevented():
    """The headline subtracts what was paid from what would have been sent.
    A refund whose outcome is unknown may have been paid; counting it as
    'would have been sent, not paid' inflated 'PrivateVault prevented'."""
    from demos.live_checkout.agent import banner, impact

    def row(i: int, **kw):
        base = dict(
            id=i,
            kind="normal",
            order_id=f"ORD-{i}",
            customer_id="C",
            requested_amount=1000,
            requested_payee="p",
            customer_text="t",
            claude_decision="issue_refund",
            claude_amount=1000,
            would_have_sent=1000,
        )
        base.update(kw)
        return Row(**base)

    rows = [
        row(1, paid=1000),
        row(2, prevented_by="tampered", prevented_amount=1000),
        row(3, outcome_unknown=True, sidecar_outcome="INDETERMINATE"),
    ]
    summary = impact(rows)
    assert summary["with_privatevault"] == 1000
    assert summary["without_privatevault"] == 2000
    assert summary["prevented"] == 1000 and summary["prevented_count"] == 1
    assert summary["outcome_unknown"] == {"count": 1, "amount": 1000, "ids": [3]}
    text = banner(summary, None)
    assert "Outcome UNKNOWN for 1 request(s)" in text and "Reconcile" in text
    # A saved run from before this field existed still loads and renders.
    old = {
        k: v for k, v in row(4, paid=1000).__dict__.items() if k != "outcome_unknown"
    }
    assert Row.from_dict(old).outcome_unknown is False
    assert "UNKNOWN" not in banner(impact([Row.from_dict(old)]), None)
