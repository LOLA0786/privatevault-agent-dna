"""Money-path attack corpus for the live refund demo.

    uv run python -m demos.live_checkout.attacks

Starts the three demo services on free loopback ports (the real PrivateVault
API, the real receiver gate, the MOCK payments API), runs each attack against
them, reads the destination ledger after every one, and prints PASS / FAIL /
NOT PREVENTED per scenario. Exit status 0 only when nothing FAILS.

``tools/run_adversarial.py`` attacks the decision engine in process. This
attacks the path the money takes: sealed decision, permit, sidecar, receiver
gate, upstream. It started as the driver for an external audit at commit
03cd1f6, which paid one refund twice (ADR 0040, ADR 0041).

Designed to be edited by a reviewer who did not write the defences: add a
function to ``SCENARIOS`` and it runs.

Statuses:
  PASS           the attack moved no money it should not have
  FAIL           money moved that should not have, or an honest payment did not
  NOT PREVENTED  a limit: the demo does not stop this, and the scenario
                 shows what does detect it (docs/WHAT-WE-DO-NOT-CLAIM.md)
  NOTE           something a scenario saw that moved no money

What this does not show: anything about a real payment provider, mutual TLS,
key custody, or a deployment where the upstream is reachable without the gate.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from agent_dna.execution_v01 import sha256_bytes_digest  # noqa: E402
from agents.core.gate import GateError, PermitBundle, wire_for  # noqa: E402
from demos.live_checkout import config as cfg  # noqa: E402
from demos.live_checkout.agent import RefundPath, verify_receipts  # noqa: E402
from demos.live_checkout.approvals import ApprovalInbox  # noqa: E402
from demos.live_checkout.bootstrap import bootstrap  # noqa: E402
from demos.live_checkout.refunds import RefundLedger, load_queue  # noqa: E402

SERVICES = ("privatevault", "gate", "payments_api")
HEALTH = {"privatevault": "/ready", "gate": "/_health", "payments_api": "/_health"}
PORT_KEY = {"privatevault": "privatevault", "gate": "gate", "payments_api": "payments"}

PASS, FAIL, NOT_PREVENTED = "PASS", "FAIL", "NOT PREVENTED"
# Things a scenario saw that moved no money but a reader should know.
OBSERVATIONS: list[str] = []


@dataclass
class Outcome:
    name: str
    status: str
    detail: str
    extra_payments: int


@dataclass
class World:
    """The three services, an approver, and a client on the money path."""

    run_dir: Path
    ports: dict[str, int]
    procs: list[subprocess.Popen[bytes]] = field(default_factory=list)
    path: RefundPath | None = None
    inbox: ApprovalInbox | None = None

    def url(self, service: str) -> str:
        return f"http://127.0.0.1:{self.ports[service]}"

    def ledger(self) -> list[dict[str, Any]]:
        """The destination ledger, read from the upstream itself."""
        with urllib.request.urlopen(self.url("payments") + "/refunds", timeout=5) as r:
            rows: list[dict[str, Any]] = json.loads(r.read())
            return rows

    def paid(self, order_id: str) -> list[int]:
        return [int(r["amount"]) for r in self.ledger() if r["order_id"] == order_id]

    # -- helpers for scenarios ------------------------------------------
    @property
    def p(self) -> RefundPath:
        assert self.path is not None
        return self.path

    def arguments(self, order_id: str, amount: int, payee: str) -> dict[str, Any]:
        return self.p.tool.arguments_for(
            {"order_id": order_id, "amount": amount, "payee": payee, "reason": "attack"}
        )

    def permit_for(self, arguments: dict[str, Any]) -> PermitBundle:
        outcome = self.p.pv.decide(self.p.tool, arguments)
        if not outcome.allowed:
            raise GateError(f"honest decide was not allowed: {outcome.reason}")
        return self.p.pv.mint(outcome, self.p.tool, arguments)

    def present(self, permit: PermitBundle, body: bytes) -> tuple[int, str | None]:
        status, payload = self.p.present(permit.header, body)
        return status, payload.get("reason_code")

    def authorize(self, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        r = self.p.pv.client.post(
            "/v1/authorize", headers=self.p.pv._headers(), json=body
        )
        try:
            payload = r.json()
        except ValueError:
            payload = {"text": r.text}
        return r.status_code, payload if isinstance(payload, dict) else {}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _wait(url: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status < 500:
                    return
        except (OSError, urllib.error.URLError) as exc:
            last = exc
            time.sleep(0.2)
    raise RuntimeError(f"{url} not ready after {timeout_s}s: {last}")


def start_world(run_dir: Path, *, without: tuple[str, ...] = ()) -> World:
    """Bootstrap and start the demo. ``without`` removes settings from the
    shipped ``services.env``, to show what the layer beneath does alone."""
    ports = {k: _free_port() for k in ("privatevault", "gate", "payments")}
    bootstrap(run_dir, force=True, ports=ports)
    if without:
        env_file = run_dir / "services.env"
        kept = [
            line
            for line in env_file.read_text().splitlines()
            if line.split("=", 1)[0] not in without
        ]
        env_file.write_text("\n".join(kept) + "\n")
    env = {k: v for k, v in os.environ.items() if not k.startswith("PV_")}
    env["PV_LIVE_RUN_DIR"] = str(run_dir)
    env["PV_LIVE_COLOR"] = "0"
    world = World(run_dir=run_dir, ports=ports)
    logs = run_dir / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    try:
        for name in SERVICES:
            world.procs.append(
                subprocess.Popen(
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
                    stdout=(logs / f"{name}.log").open("wb"),
                    stderr=subprocess.STDOUT,
                )
            )
        for name in SERVICES:
            _wait(f"http://127.0.0.1:{ports[PORT_KEY[name]]}{HEALTH[name]}")
        world.procs.append(
            subprocess.Popen(
                [
                    sys.executable,
                    str(REPO / "demos" / "live_checkout" / "approve.py"),
                    "--run-dir",
                    str(run_dir),
                    "--auto",
                    "approve",
                    "--poll",
                    "0.1",
                ],
                cwd=REPO,
                stdout=(logs / "approver.log").open("wb"),
                stderr=subprocess.STDOUT,
            )
        )
        world.inbox = ApprovalInbox(run_dir / "approvals")
        world.path = RefundPath(
            run_dir=run_dir,
            privatevault_url=world.url("privatevault"),
            gate_url=world.url("gate"),
            api_key=(run_dir / "api-key.txt").read_text().strip(),
            inbox=world.inbox,
            approval_timeout_s=60,
            ledger=RefundLedger(load_queue(), payments_url=world.url("gate")),
        )
    except BaseException:
        stop_world(world)
        raise
    return world


def stop_world(world: World) -> None:
    for proc in world.procs:
        proc.terminate()
    for proc in world.procs:
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


# --------------------------------------------------------------- scenarios
# Each returns (status, detail). The runner counts ledger entries before and
# after, so a scenario cannot pass while money it did not expect moved.

Scenario = Callable[[World], tuple[str, str]]


def honest_refund_is_paid_once(w: World) -> tuple[str, str]:
    """Control: the path pays an allowed refund, once."""
    a = w.arguments("ORD-70340", 3000, "kavya.n@okaxis")
    result = w.p.pv.dispatch(w.permit_for(a), w.p.tool, a)
    paid = w.paid("ORD-70340")
    ok = result.outcome == "EXECUTED" and paid == [3000]
    return (PASS if ok else FAIL), f"sidecar={result.outcome} paid={paid}"


def amount_changed_after_the_decision(w: World) -> tuple[str, str]:
    """Rs 3,000 was decided; Rs 30,000 is sent, five ways."""
    a = w.arguments("ORD-70263", 3000, "nb:hdfc-7781")
    permit = w.permit_for(a)
    tampered = dict(a, amount=30000)
    wire = wire_for(tampered)
    seen: list[str] = []
    seen.append(f"sidecar={w.p.pv.dispatch(permit, w.p.tool, tampered).outcome}")
    seen.append("gate={}:{}".format(*w.present(permit, wire)))
    body = dict(permit.body)
    body.update(
        action=w.p.tool.execution_action(cfg.AGENT_ID, cfg.ORGANISATION_ID, tampered),
        expected_wire_bytes_digest=sha256_bytes_digest(wire),
        expected_wire_bytes_length=len(wire),
    )
    status, _ = w.authorize(body)
    seen.append(f"remint={status}")
    bare = w.p.gate_client.post(
        cfg.REFUNDS_PATH, content=wire, headers={"Content-Type": "application/json"}
    )
    seen.append(f"no-permit={bare.status_code}")
    # The honest bytes still go afterwards: a refused attempt burns nothing.
    honest = w.p.pv.dispatch(permit, w.p.tool, a)
    seen.append(f"honest-after={honest.outcome}")
    paid = w.paid("ORD-70263")
    ok = paid == [3000] and status != 200 and bare.status_code == 403
    return (PASS if ok else FAIL), f"{' '.join(seen)} paid={paid}"


def permit_replayed(w: World) -> tuple[str, str]:
    """A used permit and its exact bytes, again: serially and eight at once."""
    a = w.arguments("ORD-70259", 2400, "rahul.m@ybl")
    permit = w.permit_for(a)
    wire = wire_for(a)
    first = w.present(permit, wire)
    serial = [w.present(permit, wire) for _ in range(3)]
    with ThreadPoolExecutor(8) as pool:
        burst = list(pool.map(lambda _: w.present(permit, wire), range(8)))
    again = w.p.pv.dispatch(permit, w.p.tool, a)
    try:
        answer = json.loads(bytes(again.transport_response or b"{}"))
    except ValueError:
        answer = {}
    if again.outcome == "EXECUTED" and answer.get("admitted") is False:
        OBSERVATIONS.append(
            "the sidecar reports outcome EXECUTED when the receiver refused the "
            f"request ({answer.get('reason_code')}): EXECUTED means the bytes were "
            "delivered, not that the receiver admitted them. No money moved. "
            "Callers check agents.core.transport.receiver_refusal() before "
            "recording a payment."
        )
    codes = Counter(s for s, _ in serial + burst)
    paid = w.paid("ORD-70259")
    ok = first[0] == 201 and set(codes) == {409} and paid == [2400]
    return (PASS if ok else FAIL), (
        f"first={first[0]} replays={dict(codes)} sidecar={again.outcome} paid={paid}"
    )


def one_permit_presented_concurrently(w: World) -> tuple[str, str]:
    """An unused permit, presented eight times at once."""
    a = w.arguments("ORD-70288", 1999, "meera.k@paytm")
    permit = w.permit_for(a)
    wire = wire_for(a)
    with ThreadPoolExecutor(8) as pool:
        codes = Counter(
            s for s, _ in pool.map(lambda _: w.present(permit, wire), range(8))
        )
    paid = w.paid("ORD-70288")
    ok = codes.get(201) == 1 and paid == [1999]
    return (PASS if ok else FAIL), f"codes={dict(codes)} paid={paid}"


def decision_minted_many_times(w: World) -> tuple[str, str]:
    """Twelve concurrent mints of one decision under new request ids."""
    a = w.arguments("ORD-70211", 1200, "ananya.s@okaxis")
    permit = w.permit_for(a)

    def remint(_: int) -> str:
        body = dict(permit.body, request_id=f"req-mint-{uuid.uuid4().hex[:8]}")
        status, payload = w.authorize(body)
        auth = payload.get("authorization") or {}
        return str(auth.get("execution_authorization_id") or f"refused:{status}")

    with ThreadPoolExecutor(8) as pool:
        ids = set(pool.map(remint, range(12))) | {permit.permit_id}
    permits = {i for i in ids if not i.startswith("refused:")}
    w.present(permit, wire_for(a))
    paid = w.paid("ORD-70211")
    ok = permits == {permit.permit_id} and paid == [1200]
    return (PASS if ok else FAIL), f"distinct_permits={len(permits)} paid={paid}"


def approval_used_twice(w: World) -> tuple[str, str]:
    """One human approval for Rs 25,000, offered to four decides."""
    assert w.inbox is not None
    a = w.arguments("ORD-70301", 25000, "card:master-9012")
    rid = w.p.pv.new_request_id()
    first = w.p.pv.decide(w.p.tool, a, request_id=rid)
    wire = wire_for(a)
    w.inbox.submit(
        request_id=rid,
        action=w.p.tool.execution_action(cfg.AGENT_ID, cfg.ORGANISATION_ID, a),
        reason=first.reason,
        wire_digest=sha256_bytes_digest(wire),
        wire_length=len(wire),
        context={"request": 0},
    )
    approval = (w.inbox.wait(rid, timeout_s=60) or {}).get("approval")
    permits: dict[str, PermitBundle] = {}
    verdicts: list[str] = []
    for request_id in (rid, rid, w.p.pv.new_request_id(), w.p.pv.new_request_id()):
        try:
            outcome = w.p.pv.decide(
                w.p.tool, a, approval=approval, request_id=request_id
            )
            verdicts.append(outcome.decision)
            if outcome.allowed:
                permit = w.p.pv.mint(outcome, w.p.tool, a)
                permits[permit.permit_id] = permit
        except GateError:
            verdicts.append("refused")
    for permit in permits.values():
        w.present(permit, wire)
    paid = w.paid("ORD-70301")
    ok = first.decision == "require_approval" and len(permits) == 1 and paid == [25000]
    return (PASS if ok else FAIL), (
        f"verdicts={verdicts} permits={len(permits)} paid={paid}"
    )


def _decide_twice(w: World, order_id: str, amount: int, payee: str) -> tuple[Any, ...]:
    a = w.arguments(order_id, amount, payee)
    first = w.p.pv.decide(w.p.tool, a)
    second = w.p.pv.decide(w.p.tool, a)
    codes: list[int] = []
    for outcome in (first, second):
        if outcome.allowed:
            try:
                permit = w.p.pv.mint(outcome, w.p.tool, a)
                codes.append(w.present(permit, wire_for(a))[0])
            except GateError:
                codes.append(0)
    return first, second, codes, w.paid(order_id)


def refund_decided_twice_before_it_is_paid(w: World) -> tuple[str, str]:
    """Two decides for one refund before either is paid (ADR 0041)."""
    first, second, codes, paid = _decide_twice(w, "ORD-70234", 850, "card:visa-4421")
    ok = (
        first.allowed
        and second.decision == "block"
        and second.triggered_by == "transaction_reservation"
        and paid == [850]
    )
    return (PASS if ok else FAIL), (
        f"decides={first.decision},{second.decision} gate={codes} paid={paid}"
    )


def refund_decided_twice_receiver_alone(w: World) -> tuple[str, str]:
    """The same, with the server's reservation removed: two permits reach
    the gate and its transaction key is all that is left (ADR 0040)."""
    first, second, codes, paid = _decide_twice(w, "ORD-70234", 850, "card:visa-4421")
    ok = first.allowed and second.allowed and sorted(codes) == [201, 409]
    ok = ok and paid == [850]
    return (PASS if ok else FAIL), (
        f"decides={first.decision},{second.decision} gate={codes} paid={paid}"
    )


def upstream_reached_without_the_gate(w: World) -> tuple[str, str]:
    """Rs 30,000 posted straight to the upstream's own port. The mock has no
    authentication; nothing in PrivateVault is on this road. What it shows:
    the payment has no admitted receipt, so reconciliation finds it."""
    body = wire_for(
        dict(w.arguments("ORD-70340", 30000, "kavya.n@okaxis"), refund_id="RF-BYPASS")
    )
    request = urllib.request.Request(
        w.url("payments") + cfg.REFUNDS_PATH,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as r:
            code = r.status
    except urllib.error.HTTPError as exc:
        code = exc.code
    unreceipted = [r["refund_id"] for r in reconcile(w)["payments_without_receipt"]]
    if code != 201:
        return PASS, f"upstream refused the direct post: {code}"
    detected = unreceipted == ["RF-BYPASS"]
    return (NOT_PREVENTED if detected else FAIL), (
        f"upstream paid it ({code}); reconciliation "
        + ("flags it: no admitted receipt" if detected else f"MISSED it: {unreceipted}")
    )


def reconcile(w: World) -> dict[str, Any]:
    """Destination ledger against the gate's signed receipts, by exact bytes."""
    from network.receiver_kit import export_receipts as exporter

    out = w.run_dir / "receipts-reconcile.jsonl"
    exporter.export(w.run_dir / "gate" / "receiver.db", out)
    receipts = [json.loads(line) for line in out.read_text().splitlines() if line]
    admitted = Counter(
        r["wire_bytes_digest"] for r in receipts if r.get("outcome") == "ADMITTED"
    )
    ledger = w.ledger()
    paid = Counter(r["body_sha256"] for r in ledger)
    return {
        "payments": len(ledger),
        "admitted_receipts": sum(admitted.values()),
        "payments_without_receipt": [
            r for r in ledger if r["body_sha256"] not in admitted
        ],
        "receipts_without_payment": sorted(set(admitted) - set(paid)),
        "paid_more_often_than_admitted": sorted(
            d for d, n in paid.items() if n > admitted.get(d, 0) > 0
        ),
    }


# name -> (scenario, extra ledger entries an honest outcome adds)
SCENARIOS: list[tuple[Scenario, int]] = [
    (honest_refund_is_paid_once, 1),
    (amount_changed_after_the_decision, 1),
    (permit_replayed, 1),
    (one_permit_presented_concurrently, 1),
    (decision_minted_many_times, 1),
    (approval_used_twice, 1),
    (refund_decided_twice_before_it_is_paid, 1),
]
RECEIVER_ALONE: list[tuple[Scenario, int]] = [(refund_decided_twice_receiver_alone, 1)]
# Run last: it puts an unreceipted payment in the ledger on purpose.
LIMITS: list[tuple[Scenario, int]] = [(upstream_reached_without_the_gate, 1)]


def _run(w: World, scenarios: list[tuple[Scenario, int]]) -> list[Outcome]:
    outcomes: list[Outcome] = []
    for scenario, expected in scenarios:
        before = len(w.ledger())
        try:
            status, detail = scenario(w)
        except Exception as exc:  # a scenario that cannot run has not passed
            status, detail = FAIL, f"{type(exc).__name__}: {exc}"
        added = len(w.ledger()) - before
        if status == PASS and added != expected:
            status = FAIL
            detail += f" (ledger grew by {added}, expected {expected})"
        outcomes.append(Outcome(scenario.__name__, status, detail, added))
    return outcomes


def run(run_dir: Path) -> dict[str, Any]:
    """Run the corpus. Returns outcomes, the reconciliation and the receipt
    verification, and writes them to ``run_dir/attacks.json``."""
    outcomes: list[Outcome] = []
    OBSERVATIONS.clear()
    shipped = start_world(run_dir / "shipped")
    try:
        outcomes += _run(shipped, SCENARIOS)
        clean = reconcile(shipped)
        receipts = verify_receipts(
            shipped.run_dir, shipped.run_dir / "gate" / "receiver.db"
        )
        outcomes += _run(shipped, LIMITS)
        ledger = shipped.ledger()
    finally:
        stop_world(shipped)
    alone = start_world(
        run_dir / "receiver-alone", without=("PV_DECIDE_TRANSACTION_KEYS",)
    )
    try:
        outcomes += _run(alone, RECEIVER_ALONE)
    finally:
        stop_world(alone)
    reconciled = (
        not clean["payments_without_receipt"]
        and not clean["receipts_without_payment"]
        and not clean["paid_more_often_than_admitted"]
        and clean["payments"] == clean["admitted_receipts"]
    )
    report = {
        "outcomes": [o.__dict__ for o in outcomes],
        "observations": sorted(set(OBSERVATIONS)),
        "reconciliation_before_limits": {**clean, "ok": reconciled},
        "receipts": receipts,
        "destination_ledger": ledger,
        "failed": [o.name for o in outcomes if o.status == FAIL]
        + ([] if reconciled else ["reconciliation"])
        + ([] if receipts.get("ok") else ["receipt verification"]),
    }
    (run_dir / "attacks.json").write_text(
        json.dumps(report, indent=2, sort_keys=True, default=str) + "\n"
    )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-dir", default=None)
    args = parser.parse_args(argv)
    run_dir = (
        Path(args.run_dir)
        if args.run_dir
        else Path(tempfile.mkdtemp(prefix="pv-attacks-"))
    )
    run_dir.mkdir(parents=True, exist_ok=True)
    report = run(run_dir)
    print("Money-path attack corpus (mock payments API on loopback)\n" + "=" * 72)
    for o in report["outcomes"]:
        print(f"[{o['status']}] {o['name']}\n       {o['detail']}")
    rec = report["reconciliation_before_limits"]
    print(
        f"[{PASS if rec['ok'] else FAIL}] ledger reconciles with signed receipts\n"
        f"       payments={rec['payments']} admitted_receipts={rec['admitted_receipts']}"
    )
    receipts = report["receipts"]
    print(
        f"[{PASS if receipts.get('ok') else FAIL}] receipts verify, and fail after "
        "one byte is changed"
    )
    for note in report["observations"]:
        print(f"[NOTE] {note}")
    counts = Counter(o["status"] for o in report["outcomes"])
    print("=" * 72)
    print(
        f"RESULT: {counts[PASS]} passed, {counts[FAIL]} failed, "
        f"{counts[NOT_PREVENTED]} not prevented (a limit, see its line)"
    )
    print(f"evidence: {run_dir / 'attacks.json'}")
    return 1 if report["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
