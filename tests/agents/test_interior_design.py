"""Persona 2, interior design firm: quotes and vendor purchase orders.

Claims -> tests:
  - A PO under the limit to an approved vendor is allowed under the grant,
    minted, dispatched once; the client quote goes out under a clearance
    -> test_po_under_limit_is_issued_once
  - A PO above the limit needs approval; the studio owner's approval turns
    it into an ALLOW whose permit names the approval
    -> test_po_above_limit_needs_approval
  - Vendor swapped after approval: refused by the sidecar and by the
    receiver; the vendor network never sees it
    -> test_vendor_swap_after_approval_is_refused
  - A PO above the hard cap and a PO to an unapproved vendor are blocked
    -> test_hard_cap_and_unapproved_vendor_are_blocked
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
from agents.personas.interior_design import tools as idt

REPO = Path(__file__).resolve().parents[2]
PERSONA = REPO / "agents" / "personas" / "interior_design"


@pytest.fixture
def runtime(tmp_path):
    with Harness.start(PERSONA / "persona.yaml", tmp_path / "run") as rt:
        yield rt


def _script(project_id: str, po_id: str) -> ScriptedModel:
    return ScriptedModel(
        [
            ToolCall("read_project_brief", {"project_id": project_id}),
            ToolCall("send_quote", {"project_id": project_id}),
            ToolCall("issue_vendor_po", {"po_id": po_id}),
            ToolCall("notify_client", {"project_id": project_id}),
            Final("done"),
        ]
    )


def test_po_under_limit_is_issued_once(runtime):
    report = runtime.run_agent(_script("PRJ-1", "PO-201"))
    quote = report.step("send_quote")
    assert quote.decision == "allow" and quote.result["quote_sent"] is True
    po = report.step("issue_vendor_po")
    assert po.decision == "allow" and po.triggered_by == "baseline"
    assert po.dispatch_outcome == "EXECUTED" and po.receiver_sequence == 1
    assert len(runtime.upstream.seen()) == 1


def test_po_above_limit_needs_approval(runtime):
    report = runtime.run_agent(_script("PRJ-1", "PO-202"))
    po = report.step("issue_vendor_po")
    assert po.first_decision == "require_approval"
    assert po.decision == "allow" and po.triggered_by == "approval"
    assert po.permit["approval_artifact_digest"] == po.approval_digest
    assert po.dispatch_outcome == "EXECUTED"


def test_vendor_swap_after_approval_is_refused(runtime):
    report = runtime.run_agent(_script("PRJ-1", "PO-202"))
    po = report.step("issue_vendor_po")
    assert po.dispatch_outcome == "EXECUTED"
    swapped = dict(po.arguments, vendor_id="VN-ATTACKER")
    result = runtime.gate.dispatch(po.permit_bundle, idt.PO_TOOL, swapped)
    assert result.sent is False
    assert result.reason_code == "EXECUTION_AUTHORIZATION_NON_CONFORMANT"
    direct = runtime.receiver.post(
        idt.PO_TOOL.receiver.path,
        content=idt.wire_for(swapped),
        headers={"X-PV-Execution-Authorization": po.permit_bundle.header},
    )
    assert direct.status_code == 403
    assert direct.json()["reason_code"] == "RECEIVER_WIRE_MISMATCH"
    assert len(runtime.upstream.seen()) == 1


def test_hard_cap_and_unapproved_vendor_are_blocked(runtime):
    po = runtime.run_agent(_script("PRJ-2", "PO-203")).step("issue_vendor_po")
    assert po.decision == "block" and "hard-cap" in (po.policy_id or "")
    po = runtime.run_agent(_script("PRJ-2", "PO-204")).step("issue_vendor_po")
    assert po.decision == "block" and "unapproved-vendor" in (po.policy_id or "")
    assert runtime.upstream.seen() == []


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
        "RECEIVER_WIRE_MISMATCH",
        "hard-cap",
        "OK ",
    ):
        assert marker in result.stdout, marker
