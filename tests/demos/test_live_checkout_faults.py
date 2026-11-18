"""Infrastructure faults around the agent (demos/live_checkout/agent.py
--all-faults): the model decides correctly; things go wrong afterwards.

Claims -> tests (the whole queue, every fault on, scripted model; the same
flags run with a real model):
  - #11: the tool multiplies the decided amount by 10 after the decision;
    nothing is paid
  - #15: request #1's used permit is presented again; nothing more is paid
  - #5: the refund call reaches two workers at the same instant; the order
    is paid once, and the other worker's attempt is recorded as refused
  - #3: the answer is lost after the payment; the row is reported as outcome
    unknown, the framework's automatic retry and the model's own retry are
    both refused, and the order is paid once
    -> test_every_fault_pays_at_most_once
"""

from __future__ import annotations

from demos.live_checkout.agent import ScriptedLLM, run_queue
from tests.demos.test_live_checkout import (
    DECISIONS,
    QUEUE,
    _approver,
    _start_world,
    _stop_world,
)


def test_every_fault_pays_at_most_once(tmp_path):
    w = _start_world(tmp_path / "run")
    approver = _approver(w, "approve")
    try:
        rows, summary, verification, _meta = run_queue(
            llm=ScriptedLLM(DECISIONS),
            queue=QUEUE,
            run_dir=w.run_dir,
            privatevault_url=w.url("privatevault"),
            gate_url=w.url("gate"),
            payments_url=w.url("gate"),
            api_key=(w.run_dir / "api-key.txt").read_text().strip(),
            approval_timeout_s=30,
            compromised_tool=True,
            bypass_sidecar=True,
            quiet=True,
            fault_race=True,
            fault_lost_response=True,
        )
        ledger = w.refunds()
    finally:
        approver.terminate()
        approver.wait(timeout=10)
        _stop_world(w)
    by_id = {r.id: r for r in rows}

    def paid(order_id):
        return [int(x["amount"]) for x in ledger if x["order_id"] == order_id]

    # 11: tampered after the decision
    assert by_id[11].dispatched_amount == 30000 and by_id[11].paid == 0
    assert paid("ORD-70340") == []
    # 15: replay of #1
    assert by_id[15].gate_status == 409 and paid("ORD-70211") == [1200]
    # 5: delivered to two workers at once
    race = by_id[5]
    assert paid("ORD-70288") == [1999] and race.paid == 1999
    [other] = race.faults
    assert other["outcome_unknown"] is False
    assert other["fault"] == "race" and other["paid"] == 0
    assert other["pv_decision"] == "block" or other["gate_status"] == 409, other
    # 3: answer lost after the payment
    lost = by_id[3]
    assert paid("ORD-70259") == [2400]
    assert lost.outcome_unknown and lost.paid == 0  # not claimed as paid
    events = {e["event"]: e for e in lost.faults}
    assert events["answer lost after delivery"]["outcome_unknown"] is True
    for retry in ("framework retried automatically", "the model retried"):
        assert events[retry]["paid"] == 0, events[retry]
        # refused outright: known not paid, not "unknown"
        assert events[retry]["outcome_unknown"] is False, events[retry]
        assert (
            events[retry]["pv_decision"] == "block"
            or events[retry]["gate_status"] == 409
        )
    # the report reads the destination ledger
    assert summary["faults"]["5"]["destination_payments"] == [1999]
    assert summary["faults"]["3"]["destination_payments"] == [2400]
    assert all(f["paid_once"] for f in summary["faults"].values())
    assert verification and verification["ok"]
