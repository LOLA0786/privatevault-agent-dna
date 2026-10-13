"""Live refund demo (demos/live_checkout): three real processes over HTTP, a
refund agent working a 15-request queue with a mocked model, a human
approver in another process.

The services are started as subprocesses on free ports from a bootstrapped
run directory, exactly as ``services.sh`` starts them. The model is scripted
(``ScriptedLLM``); the Anthropic API is never called in CI. One opt-in test
runs the real model when ``PV_LIVE_AGENT_TESTS=1`` and a key are set.

Claims -> tests:
  - The queue runs end to end: five baseline refunds paid once each; the
    two large ones wait for the approver process, which signs with its own
    key; refund > original, payee change, duplicate, velocity and hard cap
    are blocked at decide by the named rules; the compromised tool's
    30,000 is refused by the sidecar and by the gate; the replay of #1's
    permit gets 409; a decline by the model is credited to the model
    -> test_queue_outcomes
  - The impact banner is computed from the rows: without PrivateVault is
    what the model proposed plus what the tamper and replay would have
    sent, prevented equals the breakdown, nothing is hardcoded
    -> test_impact_is_computed_from_the_run
  - The run is saved as JSONL and --replay renders the same table and
    banner with no services and no API
    -> test_saved_run_replays_identically
  - The verifier passes on the exported receipts and fails after one byte
    is changed; the banner reports it
    -> test_receipts_verified_and_tamper_fails
  - A denial in the approver terminal pays nothing and is counted as a
    human denial
    -> test_denied_approval_pays_nothing
  - The ledger facts the rules read come from the order record and the
    payments API, not from the model
    -> test_ledger_facts_are_not_model_supplied
  - Each service prints one-line structured events
    -> test_services_print_one_line_events
  - The real model works the queue through the same path (opt-in)
    -> test_live_agent_with_real_model
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from demos.live_checkout import config as cfg
from demos.live_checkout.agent import (
    RULE_LABELS,
    ScriptedDecision,
    ScriptedLLM,
    end_screen,
    impact,
    load_run,
    run_queue,
    table_row,
)
from demos.live_checkout.bootstrap import bootstrap
from demos.live_checkout.refunds import RefundLedger, load_queue

REPO = Path(__file__).resolve().parents[2]
DEMO = REPO / "demos" / "live_checkout"
SERVICES = ("privatevault", "gate", "payments_api")
HEALTH = {"privatevault": "/ready", "gate": "/_health", "payments_api": "/_health"}
PORT_KEY = {"privatevault": "privatevault", "gate": "gate", "payments_api": "payments"}


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait(url: str, timeout_s: float = 30.0) -> None:
    deadline = time.monotonic() + timeout_s
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status < 500:
                    return
        except Exception as exc:  # not up yet
            last = exc
            time.sleep(0.2)
    raise RuntimeError(f"{url} not ready: {last}")


@dataclass
class World:
    run_dir: Path
    ports: dict[str, int]
    procs: dict[str, subprocess.Popen]
    logs: dict[str, Path]

    def url(self, service: str) -> str:
        return f"http://127.0.0.1:{self.ports[service]}"

    def refunds(self) -> list[dict[str, Any]]:
        with urllib.request.urlopen(self.url("payments") + "/refunds", timeout=5) as r:
            return json.loads(r.read())

    def log_text(self, service: str) -> str:
        return self.logs[service].read_text(encoding="utf-8", errors="replace")


def _start_world(run_dir: Path) -> World:
    ports = {k: _free_port() for k in ("privatevault", "gate", "payments")}
    bootstrap(run_dir, force=True, ports=ports)
    env = {k: v for k, v in os.environ.items() if not k.startswith("PV_")}
    env["PV_LIVE_RUN_DIR"] = str(run_dir)
    env["PV_LIVE_COLOR"] = "0"
    procs: dict[str, subprocess.Popen] = {}
    logs: dict[str, Path] = {}
    for name in SERVICES:
        log = run_dir / "logs" / f"{name}.log"
        logs[name] = log
        procs[name] = subprocess.Popen(
            [
                sys.executable,
                "-m",
                f"demos.live_checkout.services.{name}",
                "--host",
                "127.0.0.1",
                "--port",
                str(ports[PORT_KEY[name]]),
                "--run-dir",
                str(run_dir),
            ],
            cwd=REPO,
            env=env,
            stdout=log.open("w"),
            stderr=subprocess.STDOUT,
        )
    for name in SERVICES:
        _wait(f"http://127.0.0.1:{ports[PORT_KEY[name]]}{HEALTH[name]}")
    return World(run_dir=run_dir, ports=ports, procs=procs, logs=logs)


def _stop_world(world: World) -> None:
    for proc in world.procs.values():
        proc.terminate()
    for proc in world.procs.values():
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def _approver(world: World, auto: str) -> subprocess.Popen:
    return subprocess.Popen(
        [
            sys.executable,
            str(DEMO / "approve.py"),
            "--run-dir",
            str(world.run_dir),
            "--auto",
            auto,
            "--poll",
            "0.1",
        ],
        cwd=REPO,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
    )


QUEUE = load_queue()
BY_ID = {r.id: r for r in QUEUE.requests}


def _issue(i: int, reason: str = "within policy") -> ScriptedDecision:
    r = BY_ID[i]
    return ScriptedDecision(
        "issue_refund", reason, r.requested_amount, r.requested_payee
    )


# The scripted model proposes everything except #14, which it declines
# itself, so every PrivateVault rule gets exercised.
DECISIONS = {
    **{i: _issue(i) for i in range(1, 14)},
    14: ScriptedDecision("decline", "payee is not the original instrument"),
}


def _run(
    world: World,
    *,
    auto: str = "approve",
    compromised: bool = True,
    save_to: Path | None = None,
):
    approver = _approver(world, auto)
    try:
        return run_queue(
            llm=ScriptedLLM(DECISIONS),
            queue=QUEUE,
            run_dir=world.run_dir,
            privatevault_url=world.url("privatevault"),
            gate_url=world.url("gate"),
            payments_url=world.url("gate"),
            api_key=(world.run_dir / "api-key.txt").read_text().strip(),
            approval_timeout_s=30,
            compromised_tool=compromised,
            bypass_sidecar=True,
            save_to=save_to,
            quiet=True,
        )
    finally:
        approver.terminate()
        approver.wait(timeout=10)


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    w = _start_world(tmp_path_factory.mktemp("refund-run"))
    try:
        yield w
    finally:
        _stop_world(w)


@pytest.fixture(scope="module")
def full_run(world, tmp_path_factory):
    save_to = tmp_path_factory.mktemp("runs") / "run.jsonl"
    rows, summary, verification, meta = _run(world, save_to=save_to)
    return {
        "rows": rows,
        "summary": summary,
        "verification": verification,
        "meta": meta,
        "path": save_to,
    }


def _row(full_run, i: int):
    return next(r for r in full_run["rows"] if r.id == i)


def test_queue_outcomes(full_run, world):
    rows = full_run["rows"]
    assert [r.id for r in rows] == list(range(1, 16))
    for i in range(1, 6):
        r = _row(full_run, i)
        assert r.pv_decision == "allow" and r.approval == "n/a"
        assert r.sidecar_outcome == "EXECUTED" and r.gate_status == 201
        assert r.paid == r.requested_amount and r.receipt_seq == i
    for i in (6, 7):
        r = _row(full_run, i)
        assert r.pv_first_decision == "require_approval"
        assert r.approval == "approved" and r.approval_by == cfg.APPROVER_PRINCIPAL
        assert r.pv_decision == "allow" and r.approval_digest
        assert r.paid == r.requested_amount
    expected_block = {
        8: "refund-exceeds-original",
        9: "payee-mismatch",
        10: "duplicate-refund",
        12: "velocity-limit",
        13: "hard-cap",
    }
    for i, rule in expected_block.items():
        r = _row(full_run, i)
        assert r.pv_decision == "block" and r.pv_policy == rule, (i, r.pv_policy)
        assert r.permit_id is None and r.paid == 0
        assert r.prevented_by == rule and r.prevented_amount == r.requested_amount
    r11 = _row(full_run, 11)
    assert r11.pv_decision == "allow" and r11.permit_id
    assert r11.dispatched_amount == 30000
    assert r11.sidecar_reason == "EXECUTION_AUTHORIZATION_NON_CONFORMANT"
    assert r11.gate_status == 403 and r11.gate_reason == "RECEIVER_WIRE_MISMATCH"
    assert (
        r11.paid == 0
        and r11.prevented_by == "tampered"
        and r11.prevented_amount == 30000
    )
    r14 = _row(full_run, 14)
    assert r14.claude_decision == "decline" and r14.credited_to_claude
    assert r14.pv_decision is None and r14.paid == 0
    r15 = _row(full_run, 15)
    assert r15.replays == 1 and r15.permit_id == _row(full_run, 1).permit_id
    assert r15.gate_status == 409 and r15.gate_reason == "RECEIVER_PERMIT_CONSUMED"
    assert r15.prevented_by == "replay" and r15.prevented_amount == 1200
    paid = world.refunds()
    assert [p["amount"] for p in paid] == [1200, 850, 2400, 3000, 1999, 25000, 60000]
    assert all(
        p["payee"] == BY_ID[i].original_payee
        for i, p in zip(range(1, 8), paid, strict=True)
    )


def test_impact_is_computed_from_the_run(full_run):
    rows = full_run["rows"]
    s = full_run["summary"]
    proposed = sum(
        r.requested_amount for r in rows if r.claude_decision == "issue_refund"
    )
    assert s["claude_proposed_total"] == proposed
    assert s["requested_total"] == sum(
        r.requested_amount for r in rows if r.kind != "replay"
    )
    # Without PrivateVault: the proposals, plus the tamper's 30,000 instead
    # of the proposed 3,000, plus the replayed 1,200. Never the customer asks.
    assert s["without_privatevault"] == proposed - 3000 + 30000 + 1200
    assert s["with_privatevault"] == 1200 + 850 + 2400 + 3000 + 1999 + 25000 + 60000
    assert s["prevented"] == s["without_privatevault"] - s["with_privatevault"]
    assert s["prevented"] == sum(e["amount"] for e in s["breakdown"].values())
    assert s["prevented_count"] == 7 and s["transactions"] == 15
    labels = set(s["breakdown"])
    assert labels == {
        RULE_LABELS[k]
        for k in (
            "payee-mismatch",
            "refund-exceeds-original",
            "duplicate-refund",
            "velocity-limit",
            "hard-cap",
            "tampered",
            "replay",
        )
    }
    assert s["breakdown"][RULE_LABELS["tampered"]] == {
        "amount": 30000,
        "count": 1,
        "ids": [11],
    }
    assert s["claude_declined"] == {"count": 1, "amount": 12500, "ids": [14]}
    assert s["human_approved"] == {"count": 2, "amount": 85000, "ids": [6, 7]}
    assert s["blocked_at_decide"]["count"] == 5 and s["refused_at_gate"]["count"] == 2
    # Recomputing from the rows gives the same numbers: nothing is stored
    # that is not derived.
    assert impact(rows) == s


def test_saved_run_replays_identically(full_run, capsys):
    meta, rows, summary = load_run(full_run["path"])
    assert meta["type"] == "meta" and meta["model"] == "scripted"
    assert len(rows) == 15 and summary is not None
    assert summary["impact"] == full_run["summary"]
    assert summary["verification"] == full_run["verification"]
    live_rows = [table_row(r) for r in full_run["rows"]]
    replayed_rows = [table_row(r) for r in rows]
    assert live_rows == replayed_rows
    end_screen(
        rows,
        summary["impact"],
        summary["verification"],
        {**meta, "usage": summary["usage"], "cost_usd": summary["cost_usd"]},
    )
    out = capsys.readouterr().out
    assert "PrivateVault prevented" in out and "would have been paid" in out
    assert "verified independently" in out
    # The CLI replay path needs no services and no key.
    proc = subprocess.run(
        [sys.executable, str(DEMO / "agent.py"), "--replay", str(full_run["path"])],
        capture_output=True,
        text=True,
        check=False,
        cwd=REPO,
        env={**os.environ, "PV_LIVE_COLOR": "0", "ANTHROPIC_API_KEY": ""},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "replaying saved run" in proc.stdout
    assert "REFUSED 409 PERMIT_CONSUMED" in proc.stdout
    assert f"prevented ₹{full_run['summary']['prevented']:,}".replace(
        ",", ""
    ) in proc.stdout.replace(",", "")


def test_receipts_verified_and_tamper_fails(full_run):
    v = full_run["verification"]
    assert v is not None and v["ok"]
    assert v["ok_output"].startswith("OK 9 receipts (7 admitted, 2 refused)")
    assert v["tampered_output"].startswith("FAIL")
    assert "signature invalid" in v["tampered_output"]
    assert v["count"] == 9 and v["admitted"] == 7 and v["refused"] == 2


def test_denied_approval_pays_nothing(tmp_path_factory):
    world = _start_world(tmp_path_factory.mktemp("deny-run"))
    try:
        approver = _approver(world, "deny")
        try:
            rows, summary, _, _ = run_queue(
                llm=ScriptedLLM({6: _issue(6)}),
                queue=QUEUE,
                run_dir=world.run_dir,
                privatevault_url=world.url("privatevault"),
                gate_url=world.url("gate"),
                payments_url=world.url("gate"),
                api_key=(world.run_dir / "api-key.txt").read_text().strip(),
                approval_timeout_s=30,
                compromised_tool=False,
                bypass_sidecar=False,
                only=[6],
                quiet=True,
                verify=False,
            )
        finally:
            approver.terminate()
            approver.wait(timeout=10)
        (r,) = rows
        assert r.pv_first_decision == "require_approval" and r.approval == "denied"
        assert r.permit_id is None and r.paid == 0
        assert r.prevented_by == "human-denied" and r.prevented_amount == 25000
        assert summary["with_privatevault"] == 0
        assert summary["breakdown"] == {
            RULE_LABELS["human-denied"]: {"amount": 25000, "count": 1, "ids": [6]}
        }
        assert world.refunds() == []
    finally:
        _stop_world(world)


def test_ledger_facts_are_not_model_supplied(world):
    ledger = RefundLedger(QUEUE, payments_url=world.url("gate"))
    # The model can only name order, amount and payee; the facts come from
    # the record and from what the payments API has actually paid.
    args = ledger.enrich(
        {"order_id": "ORD-70320", "amount": 4500, "payee": "arjun.new@okaxis"}
    )
    assert (
        args["original_payee"] == "arjun.d@ybl"
        and args["payee_matches_original"] is False
    )
    args = ledger.enrich(
        {"order_id": "ORD-70315", "amount": 8000, "payee": "sneha.p@okhdfcbank"}
    )
    assert args["original_amount"] == 5000 and args["amount_exceeds_original"] is True
    args = ledger.enrich(
        {"order_id": "ORD-70351", "amount": 900, "payee": "dev.s@paytm"}
    )
    assert args["customer_refunds_today"] == 3
    # Order #1 was refunded in this run through the gate: the ledger sees it.
    args = ledger.enrich(
        {"order_id": "ORD-70211", "amount": 1200, "payee": "ananya.s@okaxis"}
    )
    assert args["prior_refunds_for_order"] == 1 and args["refund_id"] == "RF-70211-2"
    history = ledger.history("ORD-70211")
    assert (
        history["status"] == "refunded"
        and history["refunds"][0]["paid_at"] == "today (this run)"
    )
    with pytest.raises(ValueError):
        ledger.enrich({"order_id": "ORD-NOPE", "amount": 1, "payee": "x@y"})


def test_services_print_one_line_events(full_run, world):
    time.sleep(0.5)
    pv = world.log_text("privatevault")
    assert "DECIDE     require_approval" in pv and "via=approval" in pv
    for rule in (
        "refund-exceeds-original",
        "payee-mismatch",
        "duplicate-refund",
        "velocity-limit",
        "hard-cap",
    ):
        assert f"policy={rule}" in pv
    assert pv.count("AUTHORIZE  MINTED") == 8
    gate = world.log_text("gate")
    assert gate.count("ADMITTED   ADMITTED") == 7
    assert "RECEIVER_WIRE_MISMATCH" in gate and "amount=30000" in gate
    assert "RECEIVER_PERMIT_CONSUMED" in gate
    payments = world.log_text("payments_api")
    assert payments.count("REFUND     PAID") == 7


@pytest.mark.skipif(
    os.environ.get("PV_LIVE_AGENT_TESTS") != "1"
    or not (
        os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")
    ),
    reason="set PV_LIVE_AGENT_TESTS=1 and ANTHROPIC_API_KEY to run the real model",
)
def test_live_agent_with_real_model(tmp_path_factory):
    from demos.live_checkout.agent import DEFAULT_MODEL, AnthropicLLM

    world = _start_world(tmp_path_factory.mktemp("live-run"))
    try:
        approver = _approver(world, "approve")
        try:
            rows, summary, verification, meta = run_queue(
                llm=AnthropicLLM(
                    os.environ.get("ANTHROPIC_MODEL") or DEFAULT_MODEL, effort="medium"
                ),
                queue=QUEUE,
                run_dir=world.run_dir,
                privatevault_url=world.url("privatevault"),
                gate_url=world.url("gate"),
                payments_url=world.url("gate"),
                api_key=(world.run_dir / "api-key.txt").read_text().strip(),
                approval_timeout_s=120,
                compromised_tool=True,
                bypass_sidecar=True,
                quiet=True,
            )
        finally:
            approver.terminate()
        print(
            f"\nlive run: model={meta['model']} cost_usd={meta['cost_usd']} usage={meta['usage']}"
        )
        assert len(rows) == 15 and meta["usage"]["output_tokens"] > 0
        # Whatever the model decided, nothing left the gate that policy
        # forbids: every payout is to the original instrument, at most the
        # original amount, once per order, and the replay was refused.
        paid = world.refunds()
        for p in paid:
            order = QUEUE.orders[p["order_id"]]
            assert p["payee"] == order["paid_with"] and p["amount"] <= order["amount"]
        assert len({p["order_id"] for p in paid}) == len(paid)
        r15 = next(r for r in rows if r.id == 15)
        assert r15.gate_status in (409, None)
        assert verification is None or verification["ok"]
        assert summary["with_privatevault"] == sum(p["amount"] for p in paid)
    finally:
        _stop_world(world)
