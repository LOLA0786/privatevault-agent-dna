"""ADR 0043 on the live refund demo's money path (real services, mock
payments API): split-refund smurfing and the daily amount limit.

Claims -> tests:
  - Five Rs 19,999 refunds for one customer fired at once, then retried:
    three are paid, read from the destination ledger (was five, Rs 99,995)
    -> test_parallel_smurfing_pays_three
  - A customer at Rs 45,000 today: a Rs 9,000 refund is allowed (54,000), the
    next Rs 9,000 (63,000) is held for a human by the policy, and is paid
    after approval -> test_daily_amount_needs_a_human
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from agents.core.gate import wire_for
from demos.live_checkout import attacks
from demos.live_checkout.agent import RefundPath
from demos.live_checkout.approvals import ApprovalInbox
from demos.live_checkout.refunds import RefundLedger, load_queue


def _worker(w):
    return RefundPath(
        run_dir=w.run_dir,
        privatevault_url=w.url("privatevault"),
        gate_url=w.url("gate"),
        api_key=(w.run_dir / "api-key.txt").read_text().strip(),
        inbox=ApprovalInbox(w.run_dir / "approvals"),
        approval_timeout_s=30,
        ledger=RefundLedger(load_queue(), payments_url=w.url("gate")),
    )


def _refund(path, order, amount, payee):
    args = path.tool.arguments_for(
        {"order_id": order, "amount": amount, "payee": payee, "reason": "t"}
    )
    outcome = path.pv.decide(path.tool, args)
    if not outcome.allowed:
        return outcome.decision, outcome.policy_id or outcome.reason[:60]
    status, _ = path.present(
        path.pv.mint(outcome, path.tool, args).header, wire_for(args)
    )
    return "paid" if status == 201 else f"gate {status}", None


def test_parallel_smurfing_pays_three(tmp_path):
    """Five at once: at most three are paid. Then the customer keeps trying,
    one at a time, and still no more than three are ever paid. (A refund in
    the burst can also be refused because its facts went stale while another
    was paid, ADR 0045; the top-up shows the cap is three either way.)"""
    w = attacks.start_world(tmp_path / "run")
    try:
        workers = [_worker(w) for _ in range(5)]
        barrier = threading.Barrier(5)

        def go(i):
            barrier.wait()
            return _refund(workers[i], f"ORD-9000{i + 1}", 19999, "smurf.c2001@okaxis")

        with ThreadPoolExecutor(5) as pool:
            results = list(pool.map(go, range(5)))
        assert all(r[0] in ("paid", "block") for r in results), results
        burst = [r for r in w.ledger() if r["customer_id"] == "C-2001"]
        assert len(burst) <= 3, results

        for i, result in enumerate(results):  # keep trying the unpaid ones
            if result[0] != "paid":
                _refund(workers[0], f"ORD-9000{i + 1}", 19999, "smurf.c2001@okaxis")
        paid = [r for r in w.ledger() if r["customer_id"] == "C-2001"]
        assert len(paid) == 3 and sum(r["amount"] for r in paid) == 59997
    finally:
        attacks.stop_world(w)


def test_daily_amount_needs_a_human(tmp_path):
    w = attacks.start_world(tmp_path / "run")  # starts an approver that approves
    try:
        assert w.inbox is not None
        from demos.live_checkout.agent import Row

        def issue(order, amount):
            row = Row(
                id=0,
                kind="normal",
                order_id=order,
                customer_id="C-2002",
                requested_amount=amount,
                requested_payee="card:visa-2002",
                customer_text="t",
            )
            w.p.issue(
                row,
                {"order_id": order, "amount": amount, "payee": "card:visa-2002"},
                compromised=False,
                bypass_sidecar=False,
            )
            return row

        first = issue("ORD-90011", 45000)  # above 20,000: approved, paid
        assert first.paid == 45000 and first.pv_first_decision == "require_approval"
        second = issue("ORD-90012", 9000)  # 54,000 today: outright
        assert second.paid == 9000 and second.pv_first_decision == "allow"
        third = issue("ORD-90013", 9000)  # 63,000 today: held by the policy, approved
        assert third.pv_first_decision == "require_approval"
        assert third.pv_policy == "daily-amount-limit" or "daily-amount-limit" in (
            third.pv_reason or ""
        )
        assert third.paid == 9000
        assert (
            sum(r["amount"] for r in w.ledger() if r["customer_id"] == "C-2002")
            == 63000
        )
    finally:
        attacks.stop_world(w)
