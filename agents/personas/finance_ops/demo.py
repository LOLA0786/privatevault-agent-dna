"""Finance ops demo: invoice to payment instruction, with the attacks.

    uv run python agents/personas/finance_ops/demo.py

Runs in process with a scripted model and per-run keys. Six scenarios, then
the receiver's receipts are exported and checked with the independent
verifier. Exit status 0 only if every expectation holds.
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
from agents.personas.finance_ops import tools as fo  # noqa: E402

REPO = Path(__file__).resolve().parents[3]
PERSONA = Path(__file__).resolve().parent / "persona.yaml"
VERIFIER = REPO / "tools" / "verify_receiver_receipts.py"


def script(invoice_id: str) -> ScriptedModel:
    return ScriptedModel(
        [
            ToolCall("read_invoice", {"invoice_id": invoice_id}),
            ToolCall("match_purchase_order", {"invoice_id": invoice_id}),
            ToolCall("create_payment_instruction", {"invoice_id": invoice_id}),
            ToolCall("notify_ap_team", {"invoice_id": invoice_id}),
            Final("done"),
        ]
    )


class Check:
    def __init__(self) -> None:
        self.failures: list[str] = []

    def __call__(self, condition: bool, label: str) -> None:
        mark = "PASS" if condition else "FAIL"
        print(f"  [{mark}] {label}")
        if not condition:
            self.failures.append(label)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-dir", default=None)
    args = parser.parse_args(argv)
    run_dir = (
        Path(args.run_dir) if args.run_dir else Path(tempfile.mkdtemp(prefix="pv-fo-"))
    )
    check = Check()
    print(f"finance ops demo, run dir {run_dir}\n")

    with Harness.start(PERSONA, run_dir) as rt:
        print(f"agent {rt.persona.agent_id} @ {rt.persona.organisation_id}")
        print(
            f"receiver {fo.PAYMENTS.receiver_id}, receipt key {rt.receiver_public_key[:16]}..."
        )
        print(f"approver {rt.approver_kit.principal}\n")

        print("1. INV-1001: 4,200 INR to V-100, PO matched (under the grant)")
        pay = rt.run_agent(script("INV-1001")).step("create_payment_instruction")
        print(
            f"   decision={pay.decision} triggered_by={pay.triggered_by} dispatch={pay.dispatch_outcome} receiver_seq={pay.receiver_sequence}"
        )
        check(
            pay.decision == "allow" and pay.triggered_by == "baseline",
            "allowed under the grant",
        )
        check(
            pay.dispatch_outcome == "EXECUTED" and len(rt.upstream.seen()) == 1,
            "dispatched once, upstream saw it",
        )

        print("\n2. INV-1002: 18,000 INR to V-100 (above 5,000, needs approval)")
        pay2 = rt.run_agent(script("INV-1002")).step("create_payment_instruction")
        print(
            f"   first={pay2.first_decision} then decision={pay2.decision} triggered_by={pay2.triggered_by}"
        )
        print(
            f"   approval={str(pay2.approval_digest)[:24]}... permit={pay2.permit_bundle.permit_id if pay2.permit_bundle else None}"
        )
        check(
            pay2.first_decision == "require_approval",
            "first answer was require_approval",
        )
        check(
            pay2.decision == "allow" and pay2.triggered_by == "approval",
            "CFO approval turned it into ALLOW",
        )
        check(
            pay2.permit is not None
            and pay2.permit["approval_artifact_digest"] == pay2.approval_digest,
            "permit names the approval",
        )
        check(
            pay2.dispatch_outcome == "EXECUTED" and len(rt.upstream.seen()) == 2,
            "dispatched once",
        )

        print("\n3. Attack: amount changed to 48,000 after approval")
        assert pay2.permit_bundle is not None
        altered = dict(pay2.arguments, amount=48000)
        res = rt.gate.dispatch(pay2.permit_bundle, fo.PAY_TOOL, altered)
        print(f"   sidecar: outcome={res.outcome} reason={res.reason_code}")
        check(
            res.sent is False
            and res.reason_code == "EXECUTION_AUTHORIZATION_NON_CONFORMANT",
            "sidecar refused before any byte",
        )
        direct = rt.receiver.post(
            fo.PAYMENTS.path,
            content=fo.wire_for(altered),
            headers={"X-PV-Execution-Authorization": pay2.permit_bundle.header},
        )
        print(
            f"   receiver (sidecar bypassed): {direct.status_code} {direct.json().get('reason_code')}"
        )
        check(
            direct.status_code == 403
            and direct.json()["reason_code"] == "RECEIVER_WIRE_MISMATCH",
            "receiver refused the altered body",
        )
        check(len(rt.upstream.seen()) == 2, "upstream never saw the altered body")

        print("\n4. Attack: replay the consumed permit with the original body")
        replay = rt.receiver.post(
            fo.PAYMENTS.path,
            content=pay2.wire,
            headers={"X-PV-Execution-Authorization": pay2.permit_bundle.header},
        )
        print(f"   receiver: {replay.status_code} {replay.json().get('reason_code')}")
        check(
            replay.status_code == 409
            and replay.json()["reason_code"] == "RECEIVER_PERMIT_CONSUMED",
            "replay refused",
        )

        print("\n5. INV-1003: 7,000 INR to V-999 (payee not in vendor master)")
        pay3 = rt.run_agent(script("INV-1003")).step("create_payment_instruction")
        print(f"   decision={pay3.decision} policy={pay3.policy_id}")
        check(
            pay3.decision == "block" and "unknown-payee" in (pay3.policy_id or ""),
            "blocked at decide, nothing minted",
        )

        print("\n6. INV-1004: 60,000 INR to V-200 (above the hard cap)")
        pay4 = rt.run_agent(script("INV-1004")).step("create_payment_instruction")
        print(f"   decision={pay4.decision} policy={pay4.policy_id}")
        check(
            pay4.decision == "block" and "hard-cap" in (pay4.policy_id or ""),
            "blocked at decide; an approval cannot lift a block",
        )

        print("\n7. Receiver receipts, verified independently with the receiver's key")
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
                fo.PAYMENTS.receiver_id,
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
