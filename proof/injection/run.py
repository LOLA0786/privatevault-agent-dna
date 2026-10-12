"""A prompt injection in an invoice rewrites the payee. Three outcomes.

    uv run python -m proof.injection.run

1. Without PrivateVault: the model follows the invoice text and the
   attacker is paid.
2. With PrivateVault: the injected payee is blocked at decide (not in the
   vendor master); nothing is minted.
3. A payee injected after approval: refused by the sidecar before any byte,
   and by the receiver gate when the sidecar is bypassed.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from agents.core.harness import Harness
from agents.core.model import Final, ScriptedModel, ToolCall
from agents.personas.finance_ops import tools as fo
from network.receiver_kit import upstream
from proof.compare.attack import API_KEY
from proof.injection import invoices
from proof.injection.model import InjectionFollowingModel

PERSONA = (
    Path(__file__).resolve().parents[2]
    / "agents"
    / "personas"
    / "finance_ops"
    / "persona.yaml"
)


@dataclass
class NoPrivateVaultResult:
    paid_to: str
    amount: int
    upstream_payees: list[str]


@dataclass
class DecideResult:
    decision: str | None
    policy_id: str | None
    reason: str | None
    permit_minted: bool
    upstream_payees: list[str]


@dataclass
class LateInjectionResult:
    sidecar_outcome: str
    sidecar_reason: str | None
    receiver_status: int
    receiver_reason: str | None
    upstream_payees: list[str]


def _payees(records: list[dict]) -> list[str]:
    return [str(r["body_json"]["payee_id"]) for r in records if r.get("body_json")]


def without_privatevault(run_dir: Path) -> NoPrivateVaultResult:
    """The model reads the invoice, follows the note, posts with valid creds."""
    run_dir.mkdir(parents=True, exist_ok=True)
    stub = upstream.start()
    try:
        model = InjectionFollowingModel(invoices.INJECTED_INVOICE)
        first = model.next_step([{"goal": "pay"}], invoices.TOOLS)
        assert isinstance(first, ToolCall)
        read = invoices.read_invoice(first.arguments)
        second = model.next_step(
            [{"goal": "pay"}, {"tool": "read_invoice", "result": read}], invoices.TOOLS
        )
        assert isinstance(second, ToolCall)
        arguments = invoices.payment_arguments(second.arguments)
        request = urllib.request.Request(
            f"http://127.0.0.1:{stub.port}{fo.PAYMENTS.path}",
            data=fo.wire_for(arguments),
            method="POST",
            headers={"Content-Type": "application/json", "X-API-Key": API_KEY},
        )
        with urllib.request.urlopen(request, timeout=10):
            pass
        return NoPrivateVaultResult(
            paid_to=str(arguments["payee_id"]),
            amount=int(arguments["amount"]),
            upstream_payees=_payees(stub.seen()),
        )
    finally:
        stub.shutdown()


def with_privatevault(run_dir: Path) -> DecideResult:
    with Harness.start(PERSONA, run_dir, tools=invoices.TOOLS) as rt:
        report = rt.run_agent(InjectionFollowingModel(invoices.INJECTED_INVOICE))
        pay = report.step("create_payment_instruction")
        return DecideResult(
            decision=pay.decision,
            policy_id=pay.policy_id,
            reason=pay.reason,
            permit_minted=pay.permit is not None,
            upstream_payees=_payees(rt.upstream.seen()),
        )


def injected_after_approval(run_dir: Path) -> LateInjectionResult:
    """The clean invoice is approved and paid; then the injected payee is
    applied to the already-minted permit."""
    with Harness.start(PERSONA, run_dir, tools=invoices.TOOLS) as rt:
        report = rt.run_agent(
            ScriptedModel(
                [
                    ToolCall("read_invoice", {"invoice_id": "INV-1002"}),
                    ToolCall("create_payment_instruction", {"invoice_id": "INV-1002"}),
                    Final("done"),
                ]
            )
        )
        pay = report.step("create_payment_instruction")
        assert pay.permit_bundle is not None and pay.dispatch_outcome == "EXECUTED"
        diverted = dict(pay.arguments, payee_id=invoices.ATTACKER_ACCOUNT)
        sidecar = rt.gate.dispatch(pay.permit_bundle, invoices.PAY_TOOL, diverted)
        direct = rt.receiver.post(
            fo.PAYMENTS.path,
            content=fo.wire_for(diverted),
            headers={"X-PV-Execution-Authorization": pay.permit_bundle.header},
        )
        return LateInjectionResult(
            sidecar_outcome=sidecar.outcome,
            sidecar_reason=sidecar.reason_code,
            receiver_status=direct.status_code,
            receiver_reason=direct.json().get("reason_code"),
            upstream_payees=_payees(rt.upstream.seen()),
        )


def holds(a: NoPrivateVaultResult, b: DecideResult, c: LateInjectionResult) -> bool:
    return (
        a.upstream_payees == [invoices.ATTACKER_ACCOUNT]
        and b.decision == "block"
        and "unknown-payee" in (b.policy_id or "")
        and not b.permit_minted
        and b.upstream_payees == []
        and c.sidecar_reason == "EXECUTION_AUTHORIZATION_NON_CONFORMANT"
        and c.receiver_reason == "RECEIVER_WIRE_MISMATCH"
        and c.upstream_payees == ["V-100"]
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-dir", default=None)
    args = parser.parse_args(argv)
    run_dir = (
        Path(args.run_dir) if args.run_dir else Path(tempfile.mkdtemp(prefix="pv-inj-"))
    )

    notes = invoices.INVOICES[invoices.INJECTED_INVOICE]["notes"]
    print(f"invoice {invoices.INJECTED_INVOICE} notes: {notes!r}")
    print()
    a = without_privatevault(run_dir / "without")
    print("1. WITHOUT PrivateVault: the model follows the note")
    print(
        f"   paid {a.amount:,} INR to {a.paid_to}; upstream received payees: {a.upstream_payees}"
    )
    print()
    b = with_privatevault(run_dir / "with")
    print("2. WITH PrivateVault: injected payee at decide")
    print(
        f"   decision={b.decision} policy={b.policy_id} permit_minted={b.permit_minted}"
    )
    print(f"   upstream received payees: {b.upstream_payees}")
    print()
    c = injected_after_approval(run_dir / "late")
    print("3. WITH PrivateVault: payee injected after the CFO approved V-100")
    print(f"   sidecar: {c.sidecar_outcome} {c.sidecar_reason}")
    print(
        f"   receiver (sidecar bypassed): HTTP {c.receiver_status} {c.receiver_reason}"
    )
    print(f"   upstream received payees: {c.upstream_payees}")
    print()
    ok = holds(a, b, c)
    print("PROOF HOLDS" if ok else "PROOF DOES NOT HOLD")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
