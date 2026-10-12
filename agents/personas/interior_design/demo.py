"""Interior design demo: quotes and vendor purchase orders, with the attacks.

uv run python agents/personas/interior_design/demo.py
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))  # run as a script

from agents.core.harness import Harness  # noqa: E402
from agents.core.model import Final, ScriptedModel, ToolCall  # noqa: E402
from agents.personas.interior_design import tools as idt  # noqa: E402

REPO = Path(__file__).resolve().parents[3]
PERSONA = Path(__file__).resolve().parent / "persona.yaml"
VERIFIER = REPO / "tools" / "verify_receiver_receipts.py"


def script(project_id: str, po_id: str) -> ScriptedModel:
    return ScriptedModel(
        [
            ToolCall("read_project_brief", {"project_id": project_id}),
            ToolCall("send_quote", {"project_id": project_id}),
            ToolCall("issue_vendor_po", {"po_id": po_id}),
            ToolCall("notify_client", {"project_id": project_id}),
            Final("done"),
        ]
    )


class Check:
    def __init__(self) -> None:
        self.failures: list[str] = []

    def __call__(self, condition: bool, label: str) -> None:
        print(f"  [{'PASS' if condition else 'FAIL'}] {label}")
        if not condition:
            self.failures.append(label)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-dir", default=None)
    args = parser.parse_args(argv)
    run_dir = (
        Path(args.run_dir) if args.run_dir else Path(tempfile.mkdtemp(prefix="pv-id-"))
    )
    check = Check()
    print(f"interior design demo, run dir {run_dir}\n")

    with Harness.start(PERSONA, run_dir) as rt:
        print(f"agent {rt.persona.agent_id} @ {rt.persona.organisation_id}")
        print(
            f"receiver {idt.VENDOR_NETWORK.receiver_id}, approver {rt.approver_kit.principal}\n"
        )

        print(
            "1. PRJ-1 quote 480,000 INR sent; PO-201: 32,000 INR to VN-10 (under the limit)"
        )
        report = rt.run_agent(script("PRJ-1", "PO-201"))
        quote, po = report.step("send_quote"), report.step("issue_vendor_po")
        print(f"   quote decision={quote.decision} result={quote.result}")
        print(
            f"   po decision={po.decision} triggered_by={po.triggered_by} dispatch={po.dispatch_outcome} receiver_seq={po.receiver_sequence}"
        )
        check(
            quote.decision == "allow" and quote.result["quote_sent"],
            "quote sent under a clearance",
        )
        check(
            po.decision == "allow" and po.dispatch_outcome == "EXECUTED",
            "PO issued once under the grant",
        )

        print("\n2. PO-202: 120,000 INR to VN-20 (above the 50,000 limit)")
        po2 = rt.run_agent(script("PRJ-1", "PO-202")).step("issue_vendor_po")
        print(
            f"   first={po2.first_decision} then decision={po2.decision} triggered_by={po2.triggered_by}"
        )
        check(
            po2.first_decision == "require_approval",
            "first answer was require_approval",
        )
        check(
            po2.decision == "allow" and po2.triggered_by == "approval",
            "owner approval turned it into ALLOW",
        )
        check(
            po2.dispatch_outcome == "EXECUTED" and len(rt.upstream.seen()) == 2,
            "dispatched once",
        )
        assert po2.permit_bundle is not None

        print("\n3. Attack: vendor swapped to VN-ATTACKER after approval")
        swapped = dict(po2.arguments, vendor_id="VN-ATTACKER")
        res = rt.gate.dispatch(po2.permit_bundle, idt.PO_TOOL, swapped)
        print(f"   sidecar: outcome={res.outcome} reason={res.reason_code}")
        check(
            res.sent is False
            and res.reason_code == "EXECUTION_AUTHORIZATION_NON_CONFORMANT",
            "sidecar refused before any byte",
        )
        direct = rt.receiver.post(
            idt.VENDOR_NETWORK.path,
            content=idt.wire_for(swapped),
            headers={"X-PV-Execution-Authorization": po2.permit_bundle.header},
        )
        print(
            f"   receiver (sidecar bypassed): {direct.status_code} {direct.json().get('reason_code')}"
        )
        check(
            direct.status_code == 403
            and direct.json()["reason_code"] == "RECEIVER_WIRE_MISMATCH",
            "vendor network refused the altered PO",
        )
        check(len(rt.upstream.seen()) == 2, "vendor network never saw the altered PO")

        print("\n4. PO-203: 250,000 INR to VN-10 (above the hard cap)")
        po3 = rt.run_agent(script("PRJ-2", "PO-203")).step("issue_vendor_po")
        print(f"   decision={po3.decision} policy={po3.policy_id}")
        check(
            po3.decision == "block" and "hard-cap" in (po3.policy_id or ""),
            "blocked; an approval cannot lift it",
        )

        print("\n5. PO-204: 40,000 INR to VN-99 (not an approved vendor)")
        po4 = rt.run_agent(script("PRJ-2", "PO-204")).step("issue_vendor_po")
        print(f"   decision={po4.decision} policy={po4.policy_id}")
        check(
            po4.decision == "block" and "unapproved-vendor" in (po4.policy_id or ""),
            "blocked at decide",
        )

        print("\n6. Vendor network receipts, verified independently")
        out = run_dir / "receiver-receipts.jsonl"
        count = rt.export_receiver_receipts(out)
        env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
        verify = subprocess.run(
            [
                sys.executable,
                "-I",
                str(VERIFIER),
                "--jsonl",
                str(out),
                "--receiver-id",
                idt.VENDOR_NETWORK.receiver_id,
                "--receiver-key",
                f"{rt.receiver_key_id}={rt.receiver_public_key}",
            ],
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
        print(f"   exported {count} receipts; verifier: {verify.stdout.strip()}")
        check(
            verify.returncode == 0 and verify.stdout.startswith("OK"),
            "receipt chain verifies",
        )

        print("\nagent receipt log")
        print(rt.receipts.summary())
        check(rt.receipts.verify(), "agent receipt log chain intact")

    print()
    if check.failures:
        print(f"{len(check.failures)} FAILED: " + "; ".join(check.failures))
        return 1
    print("ALL SCENARIOS PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
