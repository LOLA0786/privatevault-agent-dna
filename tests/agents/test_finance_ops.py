"""Persona 1, finance ops: invoice to payment instruction through PrivateVault,
with the receiver gate as the last word.

Everything runs in process: the PrivateVault API under a test client, the
receiver gate as a reverse proxy in front of the receiver kit's stub
upstream, and the exact-byte sidecar with a demo transport. The model is
scripted; no network, no real keys.

Claims -> tests:
  - A small matched invoice is allowed under the grant, minted, dispatched
    once with the permit, and the receiver's receipt is logged
    -> test_small_matched_invoice_is_paid_once
  - An invoice above the threshold needs approval; an approval from the
    pinned CFO turns it into an ALLOW whose permit names the approval
    -> test_invoice_above_threshold_is_paid_after_approval
  - Amount changed after approval: refused by the sidecar before any byte,
    and refused by the receiver when the permit is presented directly with
    the altered body; the upstream never sees it
    -> test_amount_change_after_approval_is_refused_twice
  - Replaying a consumed permit is refused by the receiver
    -> test_replay_is_refused_by_the_receiver
  - Unknown payee and amounts above the hard cap are blocked at decide, with
    or without an approval
    -> test_unknown_payee_and_hard_cap_are_blocked
  - An approval for one invoice does not unlock another
    -> test_approval_for_other_invoice_does_not_unlock
  - Receiver receipts pass the independent verifier with the receiver's key
    -> test_receiver_receipts_verify_independently
  - The runnable demo exits 0 and reports every scenario
    -> test_demo_runs_green
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from agents.core.harness import Harness
from agents.core.model import Final, ScriptedModel, ToolCall
from agents.personas.finance_ops import tools as fo

REPO = Path(__file__).resolve().parents[2]
PERSONA = REPO / "agents" / "personas" / "finance_ops"
VERIFIER = REPO / "tools" / "verify_receiver_receipts.py"


@pytest.fixture
def runtime(tmp_path):
    with Harness.start(PERSONA / "persona.yaml", tmp_path / "run") as rt:
        yield rt


def _pay_script(invoice_id: str) -> list:
    return [
        ToolCall("read_invoice", {"invoice_id": invoice_id}),
        ToolCall("match_purchase_order", {"invoice_id": invoice_id}),
        ToolCall("create_payment_instruction", {"invoice_id": invoice_id}),
        ToolCall("notify_ap_team", {"invoice_id": invoice_id}),
        Final("done"),
    ]


def test_small_matched_invoice_is_paid_once(runtime):
    report = runtime.run_agent(ScriptedModel(_pay_script("INV-1001")))
    pay = report.step("create_payment_instruction")
    assert pay.decision == "allow" and pay.triggered_by == "baseline"
    assert pay.permit is not None and pay.dispatch_outcome == "EXECUTED"
    assert pay.receiver_receipt_digest and pay.receiver_sequence == 1
    seen = runtime.upstream.seen()
    assert len(seen) == 1 and seen[0]["body_length"] == len(pay.wire)
    notify = report.step("notify_ap_team")
    assert notify.decision == "allow" and notify.result == {"notified": "ap-team"}
    assert runtime.receipts.verify()
    entries = runtime.receipts.entries()
    assert [e["tool"] for e in entries] == [
        "create_payment_instruction",
        "notify_ap_team",
    ]


def test_invoice_above_threshold_is_paid_after_approval(runtime):
    report = runtime.run_agent(ScriptedModel(_pay_script("INV-1002")))
    pay = report.step("create_payment_instruction")
    assert pay.first_decision == "require_approval"
    assert pay.decision == "allow" and pay.triggered_by == "approval"
    assert (
        pay.approval_digest
        and pay.permit["approval_artifact_digest"] == pay.approval_digest
    )
    assert pay.dispatch_outcome == "EXECUTED"
    assert len(runtime.upstream.seen()) == 1


def test_amount_change_after_approval_is_refused_twice(runtime):
    report = runtime.run_agent(ScriptedModel(_pay_script("INV-1002")))
    pay = report.step("create_payment_instruction")
    assert pay.dispatch_outcome == "EXECUTED"
    seen_before = len(runtime.upstream.seen())

    # Attack 1: the agent process edits the amount after approval and tries
    # to dispatch under the same permit. The sidecar refuses before a byte.
    altered = dict(pay.arguments, amount=48000)
    result = runtime.gate.dispatch(pay.permit_bundle, fo.PAY_TOOL, altered)
    assert result.sent is False and result.outcome == "CONTROL_FAILURE"
    assert result.reason_code == "EXECUTION_AUTHORIZATION_NON_CONFORMANT"

    # Attack 2: skip the sidecar; present the permit to the receiver directly
    # with the altered body (a fresh permit for the same action, so the
    # refusal is the wire mismatch, not replay).
    fresh = runtime.gate.mint_again(pay.permit_bundle)
    response = runtime.receiver.post(
        fo.PAY_TOOL.receiver.path,
        content=fo.wire_for(altered),
        headers={"X-PV-Execution-Authorization": fresh.header},
    )
    assert response.status_code == 403
    assert response.json()["reason_code"] == "RECEIVER_WIRE_MISMATCH"
    assert len(runtime.upstream.seen()) == seen_before


def test_replay_is_refused_by_the_receiver(runtime):
    report = runtime.run_agent(ScriptedModel(_pay_script("INV-1001")))
    pay = report.step("create_payment_instruction")
    response = runtime.receiver.post(
        fo.PAY_TOOL.receiver.path,
        content=pay.wire,
        headers={"X-PV-Execution-Authorization": pay.permit_bundle.header},
    )
    assert response.status_code == 409
    assert response.json()["reason_code"] == "RECEIVER_PERMIT_CONSUMED"
    assert len(runtime.upstream.seen()) == 1


def test_unknown_payee_and_hard_cap_are_blocked(runtime):
    report = runtime.run_agent(ScriptedModel(_pay_script("INV-1003")))
    pay = report.step("create_payment_instruction")
    assert pay.decision == "block" and "unknown-payee" in (pay.policy_id or "")
    assert pay.permit is None and runtime.upstream.seen() == []

    report = runtime.run_agent(ScriptedModel(_pay_script("INV-1004")))
    pay = report.step("create_payment_instruction")
    assert pay.decision == "block" and "hard-cap" in (pay.policy_id or "")
    assert pay.approval_digest is None and runtime.upstream.seen() == []


def test_approval_for_other_invoice_does_not_unlock(runtime):
    # Approve INV-1002 (18,000 to V-100), then try to spend that approval on
    # INV-1005 (18,000 to V-200). The bridge refuses: different action.
    report = runtime.run_agent(ScriptedModel(_pay_script("INV-1002")))
    approval = report.step("create_payment_instruction").approval
    other = runtime.gate.decide(
        fo.PAY_TOOL, fo.payment_arguments("INV-1005"), approval=approval
    )
    assert other.decision == "require_approval"
    assert "APPROVAL_ACTION_MISMATCH" in other.reason


def test_receiver_receipts_verify_independently(runtime, tmp_path):
    runtime.run_agent(ScriptedModel(_pay_script("INV-1001")))
    runtime.run_agent(ScriptedModel(_pay_script("INV-1003")))
    out = tmp_path / "receipts.jsonl"
    count = runtime.export_receiver_receipts(out)
    assert count >= 1
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(VERIFIER),
            "--jsonl",
            str(out),
            "--receiver-id",
            fo.PAY_TOOL.receiver.receiver_id,
            "--receiver-key",
            f"{runtime.receiver_key_id}={runtime.receiver_public_key}",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.startswith("OK")


def test_demo_runs_green(tmp_path):
    result = subprocess.run(
        [sys.executable, str(PERSONA / "demo.py"), "--run-dir", str(tmp_path / "demo")],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO,
        timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "ALL SCENARIOS PASS" in result.stdout
    for marker in (
        "RECEIVER_WIRE_MISMATCH",
        "RECEIVER_PERMIT_CONSUMED",
        "triggered_by=approval",
        "unknown-payee",
        "OK ",
    ):
        assert marker in result.stdout, marker
