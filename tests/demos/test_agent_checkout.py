"""Agent checkout demo (demos/agent_checkout): a procurement agent, a mock
payment-gateway order API with a real request shape, and the receiver gate
in front of it.

Claims -> tests:
  - The honest 18,500 INR order needs approval, is minted once the
    procurement lead signs, is admitted by the gate once, and the checkout
    API creates exactly one order
    -> test_honest_order_is_created_once
  - Amount changed to 85,000 after approval and payee swapped to M-9999:
    refused by the sidecar before any byte and by the gate when the sidecar
    is bypassed; the checkout API never sees either
    -> test_post_approval_changes_are_refused_at_the_gate
  - Replaying the consumed permit with the original bytes is refused
    -> test_replay_is_refused
  - 2,50,000 INR is blocked at decide and a signed approval does not lift it
    -> test_hard_cap_blocks_and_approval_cannot_lift_it
  - Gate receipts pass the independent verifier with the gate's key, and a
    tampered export fails it (so "verified" means something)
    -> test_receipts_verify_independently
    -> test_tampered_receipts_fail_the_verifier
  - Without PrivateVault the same five requests all become orders, so the
    side-by-side is a measurement
    -> test_without_privatevault_every_request_becomes_an_order
  - The mock checkout API enforces its request shape and creates
    well-formed orders
    -> test_checkout_api_shape
  - The harness accepts a custom upstream and still refuses an altered body
    in front of it
    -> test_harness_custom_upstream_is_gated
  - report.html is one self-contained file carrying the permit id, the
    receipt hashes and the comparison
    -> test_report_is_self_contained
  - run.py --fast exits 0 and prints every scenario marker; it exits 1 when
    a check fails
    -> test_run_fast_is_green
    -> test_run_exits_nonzero_when_a_check_fails
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from agents.core.harness import Harness
from agents.core.model import Final, ScriptedModel, ToolCall
from demos.agent_checkout import checkout_api
from demos.agent_checkout import tools as ck
from demos.agent_checkout.report import write_report
from demos.agent_checkout.scenario import (
    PERSONA,
    VERIFIER,
    run_scenario,
    verify_receipts,
    without_privatevault,
)

REPO = Path(__file__).resolve().parents[2]
RUN = REPO / "demos" / "agent_checkout" / "run.py"


@pytest.fixture(scope="module")
def result(tmp_path_factory):
    """One full run of the story, shared by the read-only assertions."""
    run_dir = tmp_path_factory.mktemp("checkout-run")
    return run_scenario(run_dir)


@pytest.fixture
def runtime(tmp_path):
    with Harness.start(
        PERSONA, tmp_path / "run", tools=ck.TOOLS, upstream_factory=checkout_api.start
    ) as rt:
        yield rt


def _script(cart_id: str) -> ScriptedModel:
    return ScriptedModel(
        [
            ToolCall("read_cart", {"cart_id": cart_id}),
            ToolCall("create_checkout_order", {"cart_id": cart_id}),
            Final("done"),
        ]
    )


def _event(result, key: str):
    return next(e for e in result.events if e.key == key)


# ----------------------------------------------------------------- story


def test_honest_order_is_created_once(result):
    decide = _event(result, "decide")
    assert decide.first_decision == "require_approval"
    assert decide.decision == "allow" and decide.triggered_by == "approval"
    assert decide.permit_id and decide.approval_digest
    assert decide.permit_bound_to["approval_artifact_digest"] == decide.approval_digest
    admit = _event(result, "gate_admit")
    assert admit.sidecar_outcome == "EXECUTED"
    assert admit.api_response["status"] == "created"
    assert admit.receipt_sequence == 1 and admit.receipt_digest
    assert len(result.orders_created) == 1
    order = result.orders_created[0]
    assert order["amount"] == 18500 and order["merchant_id"] == "M-1021"
    assert order["order_id"] == "ORD-2026-7781" and order["currency"] == "INR"
    assert decide.ok and admit.ok


def test_post_approval_changes_are_refused_at_the_gate(result):
    for key in ("attack_amount", "attack_payee"):
        attack = _event(result, key)
        assert attack.sidecar_outcome == "CONTROL_FAILURE"
        assert attack.sidecar_reason == "EXECUTION_AUTHORIZATION_NON_CONFORMANT"
        assert attack.gate_status == 403
        assert attack.gate_reason == "RECEIVER_WIRE_MISMATCH"
        assert attack.receipt_digest and attack.api_orders_after == 1
        assert attack.ok
    assert _event(result, "attack_amount").request["amount"] == 85000
    assert _event(result, "attack_payee").request["merchant_id"] == "M-9999"
    # Both attacks presented the same permit the honest order was minted with.
    assert {_event(result, k).permit_id for k in ("attack_amount", "attack_payee")} == {
        _event(result, "decide").permit_id
    }


def test_replay_is_refused(result):
    replay = _event(result, "attack_replay")
    assert replay.gate_status == 409
    assert replay.gate_reason == "RECEIVER_PERMIT_CONSUMED"
    assert replay.api_orders_after == 1 and replay.ok


def test_hard_cap_blocks_and_approval_cannot_lift_it(result):
    cap = _event(result, "hard_cap")
    assert cap.request["amount"] == 250000
    assert cap.decision == "block" and cap.policy_id == "hard-cap"
    assert cap.permit_id is None
    assert cap.detail["with_approval_decision"] == "block"
    assert cap.detail["with_approval_status"] == 403
    assert cap.api_orders_after == 1 and cap.ok


def test_receipts_verify_independently(result):
    assert result.verifier_ok, result.verifier_output
    assert result.verifier_output.startswith("OK 4 receipts (1 admitted, 3 refused)")
    assert "chain+signatures" in result.verifier_output
    assert result.agent_log_ok
    receipts = [
        json.loads(line)
        for line in result.receipts_path.read_text().splitlines()
        if line.strip()
    ]
    assert [r["outcome"] for r in receipts] == [
        "ADMITTED",
        "REFUSED",
        "REFUSED",
        "REFUSED",
    ]
    assert [r["reason_code"] for r in receipts] == [
        None,
        "RECEIVER_WIRE_MISMATCH",
        "RECEIVER_WIRE_MISMATCH",
        "RECEIVER_PERMIT_CONSUMED",
    ]
    # The timeline's receipt hashes are the digests of these receipts.
    digests = {e.receipt_digest for e in result.events if e.receipt_digest}
    assert len(digests) == 4
    assert result.ok


def test_tampered_receipts_fail_the_verifier(result, tmp_path):
    """Adversarial: flip one refusal to ADMITTED in the export. The
    signature no longer matches and the chain no longer links."""
    lines = result.receipts_path.read_text().splitlines()
    second = json.loads(lines[1])
    assert second["outcome"] == "REFUSED"
    second["outcome"] = "ADMITTED"
    second["reason_code"] = None
    lines[1] = json.dumps(second, sort_keys=True)
    tampered = tmp_path / "tampered.jsonl"
    tampered.write_text("\n".join(lines) + "\n")
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    proc = subprocess.run(
        [
            sys.executable,
            "-I",
            str(VERIFIER),
            "--jsonl",
            str(tampered),
            "--receiver-id",
            result.receiver_id,
            "--receiver-key",
            f"{result.receiver_key_id}={result.receiver_public_key}",
        ],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    assert proc.returncode == 1
    assert proc.stdout.startswith("FAIL")
    assert "signature invalid" in proc.stdout
    assert "previous_receipt_digest does not link" in proc.stdout


def test_without_privatevault_every_request_becomes_an_order():
    bare = without_privatevault()
    assert (
        bare["amount_ok"] and bare["payee_ok"] and bare["replay_ok"] and bare["cap_ok"]
    )
    amounts = [o["amount"] for o in bare["orders"]]
    merchants = [o["merchant_id"] for o in bare["orders"]]
    assert amounts == [18500, 85000, 18500, 18500, 250000]
    assert merchants == ["M-1021", "M-1021", "M-9999", "M-1021", "M-1021"]


def test_side_by_side_is_consistent(result):
    rows = result.comparison
    assert len(rows) == 5
    assert all(r.without_pv_ok for r in rows)
    assert not rows[0].with_pv_refused and all(r.with_pv_refused for r in rows[1:])
    assert _event(result, "comparison").ok


# ------------------------------------------------------------ components


def _post(base: str, body: bytes) -> tuple[int, dict]:
    request = urllib.request.Request(
        base + checkout_api.ORDERS_PATH,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as resp:
            return int(resp.status), json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return int(exc.code), json.loads(exc.read())


def test_checkout_api_shape():
    api = checkout_api.start()
    try:
        good = ck.order_arguments("CART-7781")
        status, payload = _post(api.base_url, ck.wire_for(good))
        assert status == 201 and payload["status"] == "created"
        assert payload["gateway_ref"].startswith("ord_")
        assert api.orders()[0]["gateway_ref"] == payload["gateway_ref"]

        for broken in (
            {k: v for k, v in good.items() if k != "merchant_id"},
            dict(good, amount=-5),
            dict(good, amount="18500"),
            dict(good, currency="rupees"),
            dict(good, merchant_id="MERCHANT"),
            dict(good, callback_url="http://insecure.example/cb"),
            dict(good, extra="field"),
        ):
            status, payload = _post(api.base_url, json.dumps(broken).encode())
            assert status == 400 and payload["error"] == "invalid_request", broken
        status, payload = _post(api.base_url, b"not json")
        assert status == 400
        assert len(api.orders()) == 1
        assert checkout_api.validate_order(good) == []
    finally:
        api.shutdown()


def test_harness_custom_upstream_is_gated(runtime):
    assert isinstance(runtime.upstream, checkout_api.CheckoutServer)
    report = runtime.run_agent(_script("CART-7781"))
    order = report.step("create_checkout_order")
    assert order.dispatch_outcome == "EXECUTED"
    assert runtime.upstream.orders()[0]["order_id"] == "ORD-2026-7781"
    altered = dict(order.arguments, amount=85000)
    fresh = runtime.gate.mint_again(order.permit_bundle)
    direct = runtime.receiver.post(
        ck.CHECKOUT.path,
        content=ck.wire_for(altered),
        headers={"X-PV-Execution-Authorization": fresh.header},
    )
    assert direct.status_code == 403
    assert direct.json()["reason_code"] == "RECEIVER_WIRE_MISMATCH"
    assert len(runtime.upstream.orders()) == 1
    count, output, ok = verify_receipts(runtime, runtime.run_dir / "r.jsonl")
    assert ok and count == 2, output


def test_report_is_self_contained(result, tmp_path):
    out = write_report(result, tmp_path / "report.html")
    html = out.read_text(encoding="utf-8")
    assert html.startswith("<!doctype html>")
    assert "<script" not in html
    assert not re.search(r'(src|href)="https?://', html)
    assert _event(result, "decide").permit_id in html
    for event in result.events:
        if event.receipt_digest:
            assert event.receipt_digest in html
    assert "RECEIVER_WIRE_MISMATCH" in html and "RECEIVER_PERMIT_CONSUMED" in html
    assert "ALL CHECKS PASS" in html
    assert "₹2,50,000" in html  # Indian grouping for the cap
    assert result.receiver_public_key in html
    assert "<table>" in html and "Without PrivateVault" in html


def test_run_fast_is_green(tmp_path):
    proc = subprocess.run(
        [
            sys.executable,
            str(RUN),
            "--fast",
            "--color",
            "never",
            "--run-dir",
            str(tmp_path / "run"),
            "--report",
            str(tmp_path / "report.html"),
        ],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    for marker in (
        "Step 9 of 9",
        "REQUIRE_APPROVAL",
        "ALLOW  triggered_by=approval",
        "RECEIVER_WIRE_MISMATCH",
        "RECEIVER_PERMIT_CONSUMED",
        "BLOCK",
        "mode=chain+signatures",
        "without PrivateVault: all five went through",
        "with PrivateVault: all four attacks refused",
        "ALL CHECKS PASS",
    ):
        assert marker in proc.stdout, marker
    assert "\x1b[" not in proc.stdout
    assert (tmp_path / "report.html").exists()
    assert (tmp_path / "receiver-receipts.jsonl").exists()
    assert (tmp_path / "run" / "timeline.json").exists()


def test_run_exits_nonzero_when_a_check_fails(tmp_path, monkeypatch):
    """The exit status is the demo's own claim gate: break an expectation
    and it must say so."""
    import demos.agent_checkout.run as run_module
    from demos.agent_checkout import scenario

    def broken(run_dir, observer=None):
        res = scenario.run_scenario(run_dir, observer)
        res.events[0].check(False, "deliberately failed check")
        return res

    monkeypatch.setattr(run_module, "run_scenario", broken)
    code = run_module.main(
        [
            "--fast",
            "--color",
            "never",
            "--run-dir",
            str(tmp_path / "run"),
            "--report",
            str(tmp_path / "report.html"),
        ]
    )
    assert code == 1
