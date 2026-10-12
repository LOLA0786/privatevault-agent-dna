"""Property broker demo: listings, follow-ups, token payment requests, with
the attacks.

    uv run python agents/personas/property_broker/demo.py
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
from agents.personas.property_broker import tools as pb  # noqa: E402

REPO = Path(__file__).resolve().parents[3]
PERSONA = Path(__file__).resolve().parent / "persona.yaml"
VERIFIER = REPO / "tools" / "verify_receiver_receipts.py"


def script(listing_id: str, request_id: str) -> ScriptedModel:
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
        Path(args.run_dir) if args.run_dir else Path(tempfile.mkdtemp(prefix="pv-pb-"))
    )
    check = Check()
    print(f"property broker demo, run dir {run_dir}\n")

    with Harness.start(PERSONA, run_dir) as rt:
        print(f"agent {rt.persona.agent_id} @ {rt.persona.organisation_id}")
        print(
            f"receiver {pb.ESCROW.receiver_id}, escrow account {pb.ESCROW_ACCOUNT}, approver {rt.approver_kit.principal}\n"
        )

        print("1. TR-301: token 50,000 INR for L-11 into escrow (under the threshold)")
        report = rt.run_agent(script("L-11", "TR-301"))
        fu, tok = report.step("follow_up_client"), report.step("request_token_payment")
        print(
            f"   follow-up decision={fu.decision}; token decision={tok.decision} triggered_by={tok.triggered_by} dispatch={tok.dispatch_outcome} receiver_seq={tok.receiver_sequence}"
        )
        check(fu.decision == "allow", "client follow-up under a clearance")
        check(
            tok.decision == "allow" and tok.dispatch_outcome == "EXECUTED",
            "token request sent once under the grant",
        )

        print("\n2. TR-302: token 150,000 INR for L-12 (above the 100,000 threshold)")
        tok2 = rt.run_agent(script("L-12", "TR-302")).step("request_token_payment")
        print(
            f"   first={tok2.first_decision} then decision={tok2.decision} triggered_by={tok2.triggered_by}"
        )
        check(
            tok2.first_decision == "require_approval",
            "first answer was require_approval",
        )
        check(
            tok2.decision == "allow" and tok2.triggered_by == "approval",
            "principal broker's approval turned it into ALLOW",
        )
        check(
            tok2.dispatch_outcome == "EXECUTED" and len(rt.upstream.seen()) == 2,
            "dispatched once",
        )
        assert tok2.permit_bundle is not None

        print(
            "\n3. TR-303: token 50,000 INR with payee ACCT-ATTACKER (payee change at decide)"
        )
        tok3 = rt.run_agent(script("L-11", "TR-303")).step("request_token_payment")
        print(f"   decision={tok3.decision} policy={tok3.policy_id}")
        check(
            tok3.decision == "block" and "payee-not-escrow" in (tok3.policy_id or ""),
            "blocked at decide; approver never asked",
        )

        print("\n4. Attack: payee changed to ACCT-ATTACKER after approval of TR-302")
        diverted = dict(tok2.arguments, payee_id="ACCT-ATTACKER")
        res = rt.gate.dispatch(tok2.permit_bundle, pb.TOKEN_TOOL, diverted)
        print(f"   sidecar: outcome={res.outcome} reason={res.reason_code}")
        check(
            res.sent is False
            and res.reason_code == "EXECUTION_AUTHORIZATION_NON_CONFORMANT",
            "sidecar refused before any byte",
        )
        direct = rt.receiver.post(
            pb.ESCROW.path,
            content=pb.wire_for(diverted),
            headers={"X-PV-Execution-Authorization": tok2.permit_bundle.header},
        )
        print(
            f"   receiver (sidecar bypassed): {direct.status_code} {direct.json().get('reason_code')}"
        )
        check(
            direct.status_code == 403
            and direct.json()["reason_code"] == "RECEIVER_WIRE_MISMATCH",
            "escrow gate refused the diverted request",
        )
        check(len(rt.upstream.seen()) == 2, "escrow never saw the diverted request")

        print("\n5. Attack: replay the consumed permit with the original body")
        replay = rt.receiver.post(
            pb.ESCROW.path,
            content=tok2.wire,
            headers={"X-PV-Execution-Authorization": tok2.permit_bundle.header},
        )
        print(f"   receiver: {replay.status_code} {replay.json().get('reason_code')}")
        check(
            replay.status_code == 409
            and replay.json()["reason_code"] == "RECEIVER_PERMIT_CONSUMED",
            "replay refused",
        )

        print("\n6. TR-304: token 600,000 INR (above the hard cap)")
        tok4 = rt.run_agent(script("L-13", "TR-304")).step("request_token_payment")
        print(f"   decision={tok4.decision} policy={tok4.policy_id}")
        check(
            tok4.decision == "block" and "hard-cap" in (tok4.policy_id or ""),
            "blocked; an approval cannot lift it",
        )

        print("\n7. Escrow receipts, verified independently")
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
                pb.ESCROW.receiver_id,
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
