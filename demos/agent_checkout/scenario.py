"""The checkout story as data: run it, get a timeline of events.

Presentation lives in ``run.py`` (terminal) and ``report.py`` (HTML). This
module only drives the harness and records what happened at each boundary:
the decision, the approval, the permit, the sidecar, the receiver gate, the
mock checkout API, and the receipts. ``run_scenario`` calls ``observer``
after every event so a presenter can pause between steps.

``without_privatevault`` runs the same requests against a bare checkout
API with nothing in front of it, so the side-by-side comparison is a
measurement rather than a claim.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from agents.core.harness import Harness, Runtime
from agents.core.model import Final, ScriptedModel, ToolCall
from demos.agent_checkout import checkout_api
from demos.agent_checkout import tools as ck

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PERSONA = HERE / "persona.yaml"
VERIFIER = REPO / "tools" / "verify_receiver_receipts.py"
PERMIT_HEADER = "X-PV-Execution-Authorization"

HONEST_CART = "CART-7781"  # 18,500 INR to M-1021
OVER_CAP_CART = "CART-9920"  # 2,50,000 INR to M-1021
INJECTED_AMOUNT = 85000
SWAPPED_MERCHANT = "M-9999"

# A credential the agent holds in the "without PrivateVault" world. The
# mock API does not check it; the point is that the agent has one.
AGENT_API_KEY = "sk_live_agent_demo_0001"


@dataclass
class Check:
    label: str
    ok: bool


@dataclass
class Event:
    """One step of the story, with everything the report needs."""

    number: int
    key: str
    title: str
    narrative: str
    kind: str  # "order" | "attack" | "policy" | "evidence"
    request: dict[str, Any] | None = None
    decision: str | None = None
    first_decision: str | None = None
    triggered_by: str | None = None
    policy_id: str | None = None
    reason: str | None = None
    decision_id: str | None = None
    approval_digest: str | None = None
    approver: str | None = None
    permit_id: str | None = None
    permit_bound_to: dict[str, Any] | None = None
    sidecar_outcome: str | None = None
    sidecar_reason: str | None = None
    gate_status: int | None = None
    gate_reason: str | None = None
    receipt_digest: str | None = None
    receipt_sequence: int | None = None
    api_status: int | None = None
    api_response: dict[str, Any] | None = None
    api_orders_after: int | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    checks: list[Check] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)

    def check(self, condition: bool, label: str) -> None:
        self.checks.append(Check(label, bool(condition)))

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["ok"] = self.ok
        return data


@dataclass
class ComparisonRow:
    attack: str
    without_pv: str
    without_pv_ok: bool  # True means the attack went through (bad)
    with_pv: str
    with_pv_refused: bool


@dataclass
class ScenarioResult:
    run_dir: Path
    events: list[Event]
    comparison: list[ComparisonRow]
    orders_created: list[dict[str, Any]]
    receiver_id: str
    receiver_key_id: str
    receiver_public_key: str
    receipts_path: Path
    receipts_count: int
    verifier_output: str
    verifier_ok: bool
    agent_log_ok: bool
    approver: str
    agent_id: str
    organisation_id: str
    policy: dict[str, Any]

    @property
    def ok(self) -> bool:
        return all(e.ok for e in self.events) and self.verifier_ok and self.agent_log_ok

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_dir": str(self.run_dir),
            "events": [e.to_dict() for e in self.events],
            "comparison": [asdict(r) for r in self.comparison],
            "orders_created": self.orders_created,
            "receiver_id": self.receiver_id,
            "receiver_key_id": self.receiver_key_id,
            "receiver_public_key": self.receiver_public_key,
            "receipts_path": str(self.receipts_path),
            "receipts_count": self.receipts_count,
            "verifier_output": self.verifier_output,
            "verifier_ok": self.verifier_ok,
            "agent_log_ok": self.agent_log_ok,
            "approver": self.approver,
            "agent_id": self.agent_id,
            "organisation_id": self.organisation_id,
            "policy": self.policy,
            "ok": self.ok,
        }


Observer = Callable[[Event], None]


def _script(cart_id: str) -> ScriptedModel:
    return ScriptedModel(
        [
            ToolCall("read_cart", {"cart_id": cart_id}),
            ToolCall("create_checkout_order", {"cart_id": cart_id}),
            Final("done"),
        ]
    )


def _json_or_none(response: Any) -> dict[str, Any] | None:
    try:
        payload = response.json()
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None


def _present_directly(rt: Runtime, header: str, body: bytes) -> Any:
    """Skip the sidecar: present a permit and bytes to the gate ourselves."""
    return rt.receiver.post(
        ck.CHECKOUT.path, content=body, headers={PERMIT_HEADER: header}
    )


def verify_receipts(rt: Runtime, out: Path) -> tuple[int, str, bool]:
    """Export the receiver's receipts and run the independent verifier."""
    count = rt.export_receiver_receipts(out)
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(VERIFIER),
            "--jsonl",
            str(out),
            "--receiver-id",
            ck.CHECKOUT.receiver_id,
            "--receiver-key",
            f"{rt.receiver_key_id}={rt.receiver_public_key}",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    output = (result.stdout + result.stderr).strip()
    return count, output, result.returncode == 0 and result.stdout.startswith("OK")


def run_scenario(  # noqa: C901 - one linear story, step by step
    run_dir: Path, observer: Observer | None = None
) -> ScenarioResult:
    """Run the whole story. ``observer`` sees each event as it completes."""
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    events: list[Event] = []

    def emit(event: Event) -> Event:
        events.append(event)
        if observer is not None:
            observer(event)
        return event

    with Harness.start(
        PERSONA,
        run_dir,
        tools=ck.TOOLS,
        upstream_factory=checkout_api.start,
    ) as rt:
        api = rt.upstream
        assert isinstance(api, checkout_api.CheckoutServer)

        # ---- 1 + 2 + 3: the honest order --------------------------------
        report = rt.run_agent(_script(HONEST_CART), goal="check out cart CART-7781")
        read = report.step("read_cart")
        order = report.step("create_checkout_order")
        e1 = Event(
            1,
            "order",
            "Agent proposes a checkout order",
            "The procurement agent reads the cart and proposes an order of "
            "18,500 INR to merchant M-1021. The proposal is just a proposal: "
            "the agent holds no credentials and cannot reach the gateway.",
            "order",
            request=dict(order.arguments),
            detail={"cart": read.result},
        )
        e1.check(order.arguments["amount"] == 18500, "proposed amount is 18,500 INR")
        e1.check(order.arguments["merchant_id"] == "M-1021", "payee is M-1021")
        emit(e1)

        e2 = Event(
            2,
            "decide",
            "PrivateVault decides, the approver signs, a permit is minted",
            "Above 10,000 INR the policy says require_approval. The "
            "procurement lead signs an approval for exactly this action; the "
            "decision is re-asked with it and becomes ALLOW. A single-use "
            "permit is minted, bound to the amount, the payee and the exact "
            "order bytes.",
            "order",
            request=dict(order.arguments),
            decision=order.decision,
            first_decision=order.first_decision,
            triggered_by=order.triggered_by,
            policy_id=order.policy_id,
            reason=order.reason,
            decision_id=order.decision_id,
            approval_digest=order.approval_digest,
            approver=rt.approver_kit.principal,
            permit_id=None
            if order.permit_bundle is None
            else order.permit_bundle.permit_id,
        )
        if order.permit_bundle is not None:
            auth = order.permit_bundle.authorization
            e2.permit_bound_to = {
                "wire_bytes_digest": auth.get("expected_wire_bytes_digest"),
                "wire_bytes_length": auth.get("expected_wire_bytes_length"),
                "action_digest": auth.get("action_digest"),
                "approval_artifact_digest": auth.get("approval_artifact_digest"),
                "destination": auth.get("dispatch", {}).get("destination"),
                "operation": auth.get("dispatch", {}).get("operation"),
                "expires_at": auth.get("expires_at"),
            }
        e2.check(
            order.first_decision == "require_approval", "first answer: require_approval"
        )
        e2.check(
            order.decision == "allow" and order.triggered_by == "approval",
            "signed approval turned it into ALLOW",
        )
        e2.check(
            order.permit is not None
            and order.permit.get("approval_artifact_digest") == order.approval_digest,
            "permit names the approval",
        )
        e2.check(
            order.permit is not None
            and order.permit.get("expected_wire_bytes_length") == len(order.wire),
            "permit is bound to the exact order bytes",
        )
        emit(e2)

        api_response = None
        if isinstance(order.result, bytes | bytearray):
            try:
                api_response = json.loads(bytes(order.result).decode("utf-8"))
            except ValueError:
                api_response = None
        e3 = Event(
            3,
            "gate_admit",
            "Checkout gate admits the order; the API creates it once",
            "The sidecar sends the permitted bytes to the receiver gate in "
            "front of the checkout API. The gate verifies the permit against "
            "its pinned trust bundle, checks the bytes, consumes the permit, "
            "forwards once, and signs a receipt.",
            "order",
            request=dict(order.arguments),
            permit_id=e2.permit_id,
            sidecar_outcome=order.dispatch_outcome,
            sidecar_reason=order.dispatch_reason,
            gate_status=201
            if api_response and api_response.get("status") == "created"
            else None,
            gate_reason=None,
            receipt_digest=order.receiver_receipt_digest,
            receipt_sequence=order.receiver_sequence,
            api_status=201
            if api_response and api_response.get("status") == "created"
            else None,
            api_response=api_response,
            api_orders_after=len(api.seen()),
        )
        e3.check(order.dispatch_outcome == "EXECUTED", "sidecar dispatched once")
        e3.check(
            api_response is not None and api_response.get("status") == "created",
            "checkout API created the order",
        )
        e3.check(len(api.seen()) == 1, "exactly one order exists")
        e3.check(bool(order.receiver_receipt_digest), "gate signed a receipt")
        emit(e3)

        assert order.permit_bundle is not None
        permit = order.permit_bundle
        orders_before_attacks = len(api.seen())

        # ---- 4: Attack A, injected amount ---------------------------------
        altered_amount = dict(order.arguments, amount=INJECTED_AMOUNT)
        sidecar_a = rt.gate.dispatch(permit, ck.CREATE_ORDER, altered_amount)
        fresh_a = rt.gate.mint_again(permit)
        direct_a = _present_directly(rt, fresh_a.header, ck.wire_for(altered_amount))
        body_a = _json_or_none(direct_a) or {}
        e4 = Event(
            4,
            "attack_amount",
            "Attack A: prompt injection changes the amount to 85,000",
            "The merchant page carried a note telling automated agents the "
            "price was corrected to 85,000. The agent process resubmits the "
            "order with that amount under the permit minted for 18,500. The "
            "sidecar refuses before a byte leaves; with the sidecar bypassed "
            "and the permit presented straight to the gate, the gate refuses "
            "too. The checkout API never sees it.",
            "attack",
            request=altered_amount,
            permit_id=permit.permit_id,
            sidecar_outcome=sidecar_a.outcome,
            sidecar_reason=sidecar_a.reason_code,
            gate_status=direct_a.status_code,
            gate_reason=body_a.get("reason_code"),
            receipt_digest=body_a.get("receipt_digest"),
            receipt_sequence=body_a.get("receipt_sequence"),
            api_orders_after=len(api.seen()),
            detail={"injected_note": ck.INJECTED_NOTE},
        )
        e4.check(
            sidecar_a.sent is False
            and sidecar_a.reason_code == "EXECUTION_AUTHORIZATION_NON_CONFORMANT",
            "sidecar refused before any byte",
        )
        e4.check(
            direct_a.status_code == 403
            and body_a.get("reason_code") == "RECEIVER_WIRE_MISMATCH",
            "gate refused the altered bytes (RECEIVER_WIRE_MISMATCH)",
        )
        e4.check(len(api.seen()) == orders_before_attacks, "checkout API never saw it")
        emit(e4)

        # ---- 5: Attack B, swapped payee -----------------------------------
        altered_payee = dict(order.arguments, merchant_id=SWAPPED_MERCHANT)
        sidecar_b = rt.gate.dispatch(permit, ck.CREATE_ORDER, altered_payee)
        fresh_b = rt.gate.mint_again(permit)
        direct_b = _present_directly(rt, fresh_b.header, ck.wire_for(altered_payee))
        body_b = _json_or_none(direct_b) or {}
        e5 = Event(
            5,
            "attack_payee",
            "Attack B: payee swapped to M-9999",
            "Same permit, same amount, different merchant. The permit is "
            "bound to the payee as part of the action and the bytes, so the "
            "sidecar and the gate both refuse.",
            "attack",
            request=altered_payee,
            permit_id=permit.permit_id,
            sidecar_outcome=sidecar_b.outcome,
            sidecar_reason=sidecar_b.reason_code,
            gate_status=direct_b.status_code,
            gate_reason=body_b.get("reason_code"),
            receipt_digest=body_b.get("receipt_digest"),
            receipt_sequence=body_b.get("receipt_sequence"),
            api_orders_after=len(api.seen()),
        )
        e5.check(
            sidecar_b.sent is False
            and sidecar_b.reason_code == "EXECUTION_AUTHORIZATION_NON_CONFORMANT",
            "sidecar refused before any byte",
        )
        e5.check(
            direct_b.status_code == 403
            and body_b.get("reason_code") == "RECEIVER_WIRE_MISMATCH",
            "gate refused the swapped payee (RECEIVER_WIRE_MISMATCH)",
        )
        e5.check(len(api.seen()) == orders_before_attacks, "checkout API never saw it")
        emit(e5)

        # ---- 6: Attack C, replay ------------------------------------------
        replay = _present_directly(rt, permit.header, order.wire)
        body_c = _json_or_none(replay) or {}
        e6 = Event(
            6,
            "attack_replay",
            "Attack C: the used permit is replayed",
            "The exact original bytes with the exact original permit, sent "
            "again. The gate's ledger already holds this permit as consumed. "
            "No second order.",
            "attack",
            request=dict(order.arguments),
            permit_id=permit.permit_id,
            gate_status=replay.status_code,
            gate_reason=body_c.get("reason_code"),
            receipt_digest=body_c.get("receipt_digest"),
            receipt_sequence=body_c.get("receipt_sequence"),
            api_orders_after=len(api.seen()),
        )
        e6.check(
            replay.status_code == 409
            and body_c.get("reason_code") == "RECEIVER_PERMIT_CONSUMED",
            "replay refused (RECEIVER_PERMIT_CONSUMED)",
        )
        e6.check(len(api.seen()) == orders_before_attacks, "still exactly one order")
        emit(e6)

        # ---- 7: over the hard cap -----------------------------------------
        big = rt.run_agent(_script(OVER_CAP_CART), goal="check out cart CART-9920")
        cap = big.step("create_checkout_order")
        action = ck.CREATE_ORDER.execution_action(
            rt.gate.agent_id, rt.gate.organisation_id, cap.arguments
        )
        request_id = rt.gate.new_request_id()
        signed = rt.approver_kit.approve(action, request_id=request_id)
        with_approval = rt.gate.decide(
            ck.CREATE_ORDER, cap.arguments, approval=signed, request_id=request_id
        )
        e7 = Event(
            7,
            "hard_cap",
            "Over the hard cap: 2,50,000 INR is blocked at decide",
            "A second cart totals 2,50,000 INR, above the 2,00,000 hard cap. "
            "PrivateVault answers BLOCK before anyone is asked. Even a signed "
            "approval for exactly this action does not lift it: BLOCK is not "
            "a dispatchable outcome, so nothing is minted.",
            "policy",
            request=dict(cap.arguments),
            decision=cap.decision,
            first_decision=cap.first_decision,
            triggered_by=cap.triggered_by,
            policy_id=cap.policy_id,
            reason=cap.reason,
            decision_id=cap.decision_id,
            api_orders_after=len(api.seen()),
            detail={
                "with_approval_decision": with_approval.decision,
                "with_approval_policy": with_approval.policy_id,
                "with_approval_status": with_approval.status,
            },
        )
        e7.check(
            cap.decision == "block" and (cap.policy_id or "") == "hard-cap",
            "blocked by hard-cap",
        )
        e7.check(cap.permit is None, "nothing minted")
        e7.check(
            with_approval.decision == "block", "a signed approval cannot lift a BLOCK"
        )
        e7.check(len(api.seen()) == orders_before_attacks, "checkout API never saw it")
        emit(e7)

        # ---- 8: receipts, verified independently ---------------------------
        receipts_path = run_dir / "receiver-receipts.jsonl"
        count, verifier_output, verifier_ok = verify_receipts(rt, receipts_path)
        agent_log_ok = rt.receipts.verify()
        e8 = Event(
            8,
            "receipts",
            "Receipts exported and verified with the gate's public key",
            "The gate's receipt chain (one receipt per admit and per refusal) "
            "is exported to JSON Lines and checked by the standalone "
            "verifier, which does not import PrivateVault and takes the "
            "gate's public key on the command line.",
            "evidence",
            detail={
                "receipts": count,
                "verifier": verifier_output,
                "receiver_key_id": rt.receiver_key_id,
                "receiver_public_key": rt.receiver_public_key,
            },
        )
        e8.check(
            verifier_ok,
            f"verifier: {verifier_output.splitlines()[0] if verifier_output else 'no output'}",
        )
        e8.check(agent_log_ok, "agent-side receipt log chain intact")
        emit(e8)

        orders_created = api.orders()
        receiver_id = ck.CHECKOUT.receiver_id
        receiver_key_id = rt.receiver_key_id
        receiver_public_key = rt.receiver_public_key
        approver = rt.approver_kit.principal
        agent_id = rt.persona.agent_id
        organisation_id = rt.persona.organisation_id
        policy = dict(rt.persona.limits)

    # ---- 9: the same attacks with nothing in front of the API ------------
    bare = without_privatevault()
    comparison = [
        ComparisonRow(
            "Honest order, 18,500 to M-1021",
            bare["honest"],
            True,
            f"created once, gate receipt #{e3.receipt_sequence}",
            False,
        ),
        ComparisonRow(
            "A. amount \u2192 85,000 after approval",
            bare["amount"],
            bare["amount_ok"],
            f"refused {e4.gate_reason}",
            e4.gate_reason == "RECEIVER_WIRE_MISMATCH",
        ),
        ComparisonRow(
            "B. payee \u2192 M-9999 after approval",
            bare["payee"],
            bare["payee_ok"],
            f"refused {e5.gate_reason}",
            e5.gate_reason == "RECEIVER_WIRE_MISMATCH",
        ),
        ComparisonRow(
            "C. used permit replayed",
            bare["replay"],
            bare["replay_ok"],
            f"refused {e6.gate_reason}",
            e6.gate_reason == "RECEIVER_PERMIT_CONSUMED",
        ),
        ComparisonRow(
            "D. 2,50,000, over the hard cap",
            bare["cap"],
            bare["cap_ok"],
            f"blocked at decide ({e7.policy_id})",
            e7.decision == "block",
        ),
    ]
    e9 = Event(
        9,
        "comparison",
        "Side by side: without PrivateVault, every attack goes through",
        "The same five requests against the same checkout API with nothing "
        "in front of it and the agent holding a valid API key. The API does "
        "its job: every well-formed request becomes an order.",
        "evidence",
        detail={
            "without_pv_orders": bare["orders"],
            "rows": [asdict(r) for r in comparison],
        },
    )
    e9.check(
        all(r.without_pv_ok for r in comparison),
        "without PrivateVault: all five went through",
    )
    e9.check(
        all(r.with_pv_refused for r in comparison[1:]),
        "with PrivateVault: all four attacks refused",
    )
    events.append(e9)
    if observer is not None:
        observer(e9)

    result = ScenarioResult(
        run_dir=run_dir,
        events=events,
        comparison=comparison,
        orders_created=orders_created,
        receiver_id=receiver_id,
        receiver_key_id=receiver_key_id,
        receiver_public_key=receiver_public_key,
        receipts_path=receipts_path,
        receipts_count=count,
        verifier_output=verifier_output,
        verifier_ok=verifier_ok,
        agent_log_ok=agent_log_ok,
        approver=approver,
        agent_id=agent_id,
        organisation_id=organisation_id,
        policy=policy,
    )
    (run_dir / "timeline.json").write_text(
        json.dumps(result.to_dict(), indent=2, sort_keys=True, default=str),
        encoding="utf-8",
    )
    return result


def _post_bare(base_url: str, body: bytes) -> tuple[int, dict[str, Any] | None]:
    request = urllib.request.Request(
        base_url + checkout_api.ORDERS_PATH,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {AGENT_API_KEY}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            status = int(response.status)
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        try:
            payload = json.loads(exc.read().decode("utf-8"))
        except ValueError:
            payload = None
    return status, payload if isinstance(payload, dict) else None


def without_privatevault() -> dict[str, Any]:
    """The same five requests with nothing between the agent and the API."""
    api = checkout_api.start()
    try:
        honest = ck.order_arguments(HONEST_CART)
        base = api.base_url

        def describe(status: int, payload: dict[str, Any] | None) -> str:
            if status == 201 and payload is not None:
                return f"201 created {payload.get('gateway_ref')}"
            return f"HTTP {status}"

        s0, p0 = _post_bare(base, ck.wire_for(honest))
        s1, p1 = _post_bare(base, ck.wire_for(dict(honest, amount=INJECTED_AMOUNT)))
        s2, p2 = _post_bare(
            base, ck.wire_for(dict(honest, merchant_id=SWAPPED_MERCHANT))
        )
        s3, p3 = _post_bare(base, ck.wire_for(honest))  # replay of the honest bytes
        s4, p4 = _post_bare(base, ck.wire_for(ck.order_arguments(OVER_CAP_CART)))
        return {
            "honest": describe(s0, p0),
            "amount": describe(s1, p1),
            "amount_ok": s1 == 201,
            "payee": describe(s2, p2),
            "payee_ok": s2 == 201,
            "replay": describe(s3, p3) + " (duplicate)"
            if s3 == 201
            else describe(s3, p3),
            "replay_ok": s3 == 201,
            "cap": describe(s4, p4),
            "cap_ok": s4 == 201,
            "orders": api.orders(),
        }
    finally:
        api.shutdown()
