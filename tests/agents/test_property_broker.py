"""Persona 3, property broker: listings, client follow-ups, token payment
requests. The only payee a token request may name is the brokerage's escrow
account; any other payee is blocked at decide, and a payee changed after
approval is refused at the sidecar and the receiver.

Claims -> tests:
  - A token request to the escrow account under the threshold is allowed,
    minted, dispatched once; the follow-up goes out under a clearance
    -> test_token_request_to_escrow_is_sent_once
  - A token request above the threshold needs the principal broker's
    approval and then executes
    -> test_large_token_request_needs_approval
  - A payee other than escrow is blocked at decide, with or without approval
    -> test_payee_change_is_blocked_at_decide
  - Payee changed after approval: refused by the sidecar and the receiver
    -> test_payee_change_after_approval_is_refused
  - The demo runs green
    -> test_demo_runs_green
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from agents.core.harness import Harness
from agents.core.model import Final, ScriptedModel, ToolCall
from agents.personas.property_broker import tools as pb

REPO = Path(__file__).resolve().parents[2]
PERSONA = REPO / "agents" / "personas" / "property_broker"


@pytest.fixture
def runtime(tmp_path):
    with Harness.start(PERSONA / "persona.yaml", tmp_path / "run") as rt:
        yield rt


def _script(listing_id: str, request_id: str) -> ScriptedModel:
    return ScriptedModel(
        [
            ToolCall("list_properties", {"area": "Koramangala"}),
            ToolCall(
                "follow_up_client", {"client_id": "C-7", "listing_id": listing_id}
            ),
            ToolCall("request_token_payment", {"request_id": request_id}),
            ToolCall(
                "schedule_viewing", {"client_id": "C-7", "listing_id": listing_id}
            ),
            Final("done"),
        ]
    )


def test_token_request_to_escrow_is_sent_once(runtime):
    report = runtime.run_agent(_script("L-11", "TR-301"))
    assert report.step("follow_up_client").decision == "allow"
    token = report.step("request_token_payment")
    assert token.decision == "allow" and token.triggered_by == "baseline"
    assert token.arguments["payee_id"] == pb.ESCROW_ACCOUNT
    assert token.dispatch_outcome == "EXECUTED" and token.receiver_sequence == 1
    assert len(runtime.upstream.seen()) == 1


def test_large_token_request_needs_approval(runtime):
    token = runtime.run_agent(_script("L-12", "TR-302")).step("request_token_payment")
    assert token.first_decision == "require_approval"
    assert token.decision == "allow" and token.triggered_by == "approval"
    assert token.permit["approval_artifact_digest"] == token.approval_digest
    assert token.dispatch_outcome == "EXECUTED"


def test_payee_change_is_blocked_at_decide(runtime):
    token = runtime.run_agent(_script("L-11", "TR-303")).step("request_token_payment")
    assert token.decision == "block" and "payee-not-escrow" in (token.policy_id or "")
    assert token.permit is None and runtime.upstream.seen() == []
    # Even with a willing approver the block stands: the approver was never
    # asked, because BLOCK is not approvable.
    assert token.approval is None


def test_payee_change_after_approval_is_refused(runtime):
    token = runtime.run_agent(_script("L-12", "TR-302")).step("request_token_payment")
    assert token.dispatch_outcome == "EXECUTED"
    diverted = dict(token.arguments, payee_id="ACCT-ATTACKER")
    result = runtime.gate.dispatch(token.permit_bundle, pb.TOKEN_TOOL, diverted)
    assert result.sent is False
    assert result.reason_code == "EXECUTION_AUTHORIZATION_NON_CONFORMANT"
    direct = runtime.receiver.post(
        pb.TOKEN_TOOL.receiver.path,
        content=pb.wire_for(diverted),
        headers={"X-PV-Execution-Authorization": token.permit_bundle.header},
    )
    assert direct.status_code == 403
    assert direct.json()["reason_code"] == "RECEIVER_WIRE_MISMATCH"
    assert len(runtime.upstream.seen()) == 1


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
        "triggered_by=approval",
        "payee-not-escrow",
        "RECEIVER_WIRE_MISMATCH",
        "RECEIVER_PERMIT_CONSUMED",
        "OK ",
    ):
        assert marker in result.stdout, marker
