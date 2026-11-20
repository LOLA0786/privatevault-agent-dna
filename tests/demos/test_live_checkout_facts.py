"""ADR 0045 on the live refund demo: refund facts are checked against the
payments API's own records (refund-facts/1).

Claims -> tests:
  - A refund made in the payments system while a Rs 25,000 approval waits is
    caught when the approval lands: the approved decide is refused as stale
    and nothing more is paid (was: Rs 30,000 refunded on a Rs 25,000 order)
    -> test_refund_during_approval_wait_is_caught
  - A tool that states false facts is refused: no prior refunds on an order
    that has one, another customer, an amount it does not exceed
    -> test_false_facts_are_refused[*]
  - When the system of record cannot be read the decide is refused
    -> test_unreadable_source_refuses
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
import urllib.request

import pytest

from demos.live_checkout import attacks
from demos.live_checkout.agent import Row
from demos.live_checkout.refunds import load_queue


def test_refund_during_approval_wait_is_caught(tmp_path):
    w = attacks.start_world(tmp_path / "run")
    try:
        approver = w.procs[-1]
        approver.terminate()
        approver.wait(10)  # no auto-approval: we hold the human
        req = next(
            r for r in load_queue().requests if r.id == 6
        )  # Rs 25,000, ORD-70301
        row = Row(
            id=6,
            kind=req.kind,
            order_id=req.order_id,
            customer_id=req.customer_id,
            requested_amount=req.requested_amount,
            requested_payee=req.requested_payee,
            customer_text=req.text,
        )
        worker = threading.Thread(
            target=lambda: w.p.issue(
                row,
                {"order_id": "ORD-70301", "amount": 25000, "payee": "card:master-9012"},
                compromised=False,
                bypass_sidecar=False,
            )
        )
        worker.start()
        time.sleep(3)  # the approval request is waiting
        desk = json.dumps(
            {
                "refund_id": "RF-70301-DESK",
                "order_id": "ORD-70301",
                "customer_id": "C-1006",
                "amount": 5000,
                "currency": "INR",
                "payee": "card:master-9012",
            }
        ).encode()
        urllib.request.urlopen(
            urllib.request.Request(
                w.url("payments") + "/v1/refunds",
                data=desk,
                headers={"Content-Type": "application/json"},
                method="POST",
            ),
            timeout=5,
        )
        approve = subprocess.Popen(
            [
                sys.executable,
                "demos/live_checkout/approve.py",
                "--run-dir",
                str(w.run_dir),
                "--auto",
                "approve",
                "--poll",
                "0.1",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        worker.join(60)
        approve.terminate()
        assert row.pv_first_decision == "require_approval"
        assert row.pv_decision == "block", row
        assert "FACTS_MISMATCH" in (row.pv_reason or "")
        assert "prior_refunds_for_order: stated 0, system of record 1" in row.pv_reason
        paid = [
            (r["refund_id"], r["amount"])
            for r in w.ledger()
            if r["order_id"] == "ORD-70301"
        ]
        assert paid == [("RF-70301-DESK", 5000)]
    finally:
        attacks.stop_world(w)


@pytest.mark.parametrize(
    "order, amount, payee, lie, field",
    [
        (
            "ORD-70333",
            1800,
            "card:visa-1178",
            {"prior_refunds_for_order": 0},
            "prior_refunds_for_order",
        ),
        (
            "ORD-70211",
            1200,
            "ananya.s@okaxis",
            {"customer_id": "C-9999"},
            "customer_id",
        ),
        (
            "ORD-70315",
            8000,
            "sneha.p@okhdfcbank",
            {"amount_exceeds_original": False},
            "amount_exceeds_original",
        ),
    ],
    ids=["no-prior-refunds", "other-customer", "not-over-original"],
)
def test_false_facts_are_refused(tmp_path, order, amount, payee, lie, field):
    w = attacks.start_world(tmp_path / "run")
    try:
        honest = w.arguments(order, amount, payee)
        lying = {**honest, **lie}
        outcome = w.p.pv.decide(w.p.tool, lying)
        assert outcome.decision == "block" and "FACTS_MISMATCH" in outcome.reason
        assert f"{field}: stated {lie[field]!r}" in outcome.reason
        assert w.paid(order) == []
    finally:
        attacks.stop_world(w)


def test_unreadable_source_refuses(tmp_path):
    w = attacks.start_world(tmp_path / "run")
    try:
        args = w.arguments("ORD-70211", 1200, "ananya.s@okaxis")
        payments = w.procs[2]
        payments.terminate()
        payments.wait(10)
        outcome = w.p.pv.decide(w.p.tool, args)
        assert outcome.decision == "block" and "FACTS_UNAVAILABLE" in outcome.reason
    finally:
        attacks.stop_world(w)
