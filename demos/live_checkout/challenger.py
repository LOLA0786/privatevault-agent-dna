"""Continuous challenger: a pen tester on every approved action, the moment
it leaves the model.

    uv run python -m demos.live_checkout.challenger --minutes 10
    uv run python -m demos.live_checkout.challenger --actions 40 --seed 7
    uv run python -m demos.live_checkout.challenger --forever --stop-on-failure

Each cycle the agent side proposes a refund on a fresh order from a synthetic
order book. PrivateVault decides it (with a human approval when the policy
asks) and mints a single-use permit. While that approved action is live, the
challenger attacks it the way a pen tester would; then the honest request is
sent once; then it attacks the spent action again. Every challenge is judged
by the payments ledger (the money), not by status codes alone.

Verdicts:
  CAUGHT      refused, and no money moved that should not have
  PAID        the honest request was paid, exactly once
  ESCAPED     money moved that should not have, or a permit was minted for
              bytes nobody decided                                   (fails)
  DENIED      the honest refund was not paid                         (fails)
  LAYER_MISS  no money moved, but a layer that claims to refuse did not
              (for example the sidecar sent mutated bytes and only the gate
              caught them)                                           (fails)
  BOUNDARY    the documented open boundary: the mock payments API pays a
              request that never went through the gate; reconciliation must
              flag it (docs/WHAT-WE-DO-NOT-CLAIM.md). Fails with
              --boundary-closed, for a deployment where it must be closed
  LEAK        the refund grant was charged for money that was never paid
              without approval (a refused or unexecuted decide)       (fails)
  BLIND       a planted bypass or tamper went undetected: the checks that
              judge everything else cannot see                       (fails)
  ERROR       a challenge could not run                              (fails)

The challenger attacks its own copy of the stack (its own keys, receipts and
ledger, a synthetic order book), never production. The controls it probes are
stateful: probing single-use permits, refund keys and per-customer daily
counters on live state would spend real customers' limits, and an escape
would move real money. Point it at a sandbox counterparty, never a live one.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import random
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

QUEUE_ENV = "LIVE_CHECKOUT_QUEUE_FILE"
BANKS = ("okaxis", "ybl", "paytm", "okhdfcbank", "oksbi")
ATTACKER_PAYEES = (
    "refund.desk@okicici",
    "mule.acct@ybl",
    "card:visa-0000",
    "nb:sbi-9999",
)
FAILING = {"ESCAPED", "DENIED", "LAYER_MISS", "LEAK", "BLIND", "ERROR"}
SIDECAR_REFUSED = {"NOT_SENT", "CONTROL_FAILURE"}
VELOCITY_LIMIT = 3  # persona.yaml: a 4th refund for one customer in a day

# challenge name -> the claims it puts under test (numbered as in the brief)
CLAIMS = {
    "amount_changed": "6,8",
    "payee_changed": "6,8",
    "byte_smuggled": "6",
    "permit_forged": "4",
    "permit_swapped": "4,7",
    "no_permit": "7",
    "remint_tampered": "4",
    "facts_overpay": "11",
    "facts_identity": "11",
    "approval_other_order": "10",
    "approval_amount_raised": "10",
    "honest_send": "6,7",
    "first_use_race": "7,9",
    "replay_serial": "4,7,9",
    "replay_burst": "4,7,9",
    "sidecar_retry": "9",
    "redecide": "7,9",
    "stale_facts": "11",
    "money_oracle": "9",
    "velocity_race": "10",
    "upstream_direct": "16",
    "receipts_drill": "5",
    "reconcile": "7,9",
    "budget_oracle": "budget",
}


# --------------------------------------------------------------- order book
@dataclass
class Order:
    order_id: str
    customer_id: str
    amount: int  # what the agent will ask to refund
    payee: str


@dataclass
class Book:
    honest: list[Order]
    decoys: list[Order]  # small one-order customers: forged facts, swaps, bypass
    big_decoys: list[Order]  # above the approval threshold: approval binding
    probes: list[list[Order]]  # six small orders per customer: velocity races


def build_book(path: Path, rng: random.Random, scale: float = 1.0) -> Book:
    """Write a synthetic order book next to the fixture's own orders. Honest
    customers never share an order with a decoy, so a deliberate bypass
    payment can never push an honest customer over a limit."""
    raw = json.loads((HERE / "refund_queue.json").read_text(encoding="utf-8"))
    book = copy.deepcopy(raw)
    day = book["day"]
    serial = iter(range(1, 10**6))
    customer = iter(range(7000, 10**6))
    out = Book([], [], [], [])

    def add(amount: int, cid: str, payee: str) -> str:
        oid = f"ORD-{90000 + next(serial)}"
        book["orders"][oid] = {
            "customer_id": cid,
            "amount": amount,
            "paid_with": payee,
            "paid_at": f"{day}T09:00:00Z",
            "status": "delivered",
            "items": "synthetic order (challenger)",
            "refunds": [],
        }
        return oid

    def new_customer() -> tuple[str, str]:
        n = next(customer)
        return f"C-{n}", f"cust{n}@{rng.choice(BANKS)}"

    for _ in range(max(1, int(120 * scale))):  # two orders each: well under every limit
        cid, payee = new_customer()
        for _ in range(2):
            big = rng.random() < 0.15
            amount = (
                rng.randrange(21000, 30000, 50)
                if big
                else rng.randrange(600, 19000, 50)
            )
            ask = (
                amount
                if rng.random() < 0.6
                else rng.randrange(max(100, amount // 2), amount, 10)
            )
            out.honest.append(Order(add(amount, cid, payee), cid, ask, payee))
    for _ in range(max(1, int(650 * scale))):
        cid, payee = new_customer()
        amount = rng.randrange(600, 6000, 50)
        out.decoys.append(Order(add(amount, cid, payee), cid, amount, payee))
    for _ in range(max(1, int(40 * scale))):
        cid, payee = new_customer()
        amount = rng.randrange(21000, 30000, 50)
        out.big_decoys.append(Order(add(amount, cid, payee), cid, amount, payee))
    for _ in range(max(1, int(35 * scale))):
        cid, payee = new_customer()
        orders = []
        for _ in range(6):
            amount = rng.randrange(600, 4000, 50)
            orders.append(Order(add(amount, cid, payee), cid, amount, payee))
        out.probes.append(orders)
    path.write_text(json.dumps(book, indent=1), encoding="utf-8")
    rng.shuffle(out.honest)
    return out


# ------------------------------------------------------------ the challenge
@dataclass
class Approved:
    seq: int
    order: Order
    args: dict[str, Any]
    wire: bytes
    permit: Any  # agents.core.gate.PermitBundle
    approval: dict[str, Any] | None

    @property
    def refund_id(self) -> str:
        return str(self.args["refund_id"])


@dataclass
class Ctx:
    w: Any  # demos.live_checkout.attacks.World
    rng: random.Random
    act: Approved
    decoys: Iterator[Order]
    big_decoys: Iterator[Order]
    probes: Iterator[list[Order]]
    probe: list[Order] | None = None  # the velocity race's customer, now at the limit
    race_paid: int = 0  # rupees the velocity race paid, without approval


Result = tuple[str, str, int]  # verdict, detail, ledger rows the challenge may add


class NoHonestPathError(Exception):
    """The honest action could not be approved: a DENIED, not an attack."""


def _m() -> Any:
    """The demo modules, imported after the order book path is set."""
    import demos.live_checkout.attacks as atk

    return atk


def _reason(out: Any) -> str:
    return f"{out.decision}/{out.triggered_by}: {str(out.reason)[:110]}"


def _mutate(args: dict[str, Any], **changes: Any) -> dict[str, Any]:
    """Change what the attacker wants and keep the derived facts consistent,
    so the only thing wrong is the change itself."""
    out = dict(args, **changes)
    if "amount" in changes:
        out["amount_exceeds_original"] = out["amount"] > out["original_amount"]
        out["customer_amount_today_after"] = (
            args["customer_amount_today_after"] - args["amount"] + out["amount"]
        )
    if "payee" in changes:
        out["payee_matches_original"] = out["payee"] == out["original_payee"]
    return out


def _both_layers(c: Ctx, tampered: dict[str, Any], what: str) -> Result:
    """Claims 6 and 8: the sidecar sends nothing, the gate refuses the bypass."""
    atk = _m()
    res = c.w.p.pv.dispatch(c.act.permit, c.w.p.tool, tampered)
    status, code = c.w.present(c.act.permit, atk.wire_for(tampered))
    detail = f"{what}: sidecar={res.outcome}:{getattr(res, 'reason_code', None)} gate={status}:{code}"
    # exact_byte_http: NOT_SENT / CONTROL_FAILURE = transport never invoked, permit not burned
    held = (
        res.outcome in SIDECAR_REFUSED
        and status == 403
        and code == "RECEIVER_WIRE_MISMATCH"
    )
    return ("CAUGHT" if held else "LAYER_MISS"), detail, 0


def amount_changed(c: Ctx) -> Result:
    a = c.act.args["amount"]
    delta = c.rng.choice([1, 10, 100, a, 9 * a])
    new = a - delta if (c.rng.random() < 0.3 and a - delta > 0) else a + delta
    return _both_layers(c, _mutate(c.act.args, amount=new), f"amount {a}->{new}")


def payee_changed(c: Ctx) -> Result:
    payee = c.rng.choice(ATTACKER_PAYEES)
    return _both_layers(c, _mutate(c.act.args, payee=payee), f"payee->{payee}")


def byte_smuggled(c: Ctx) -> Result:
    """Same JSON meaning, other bytes: exact-byte binding must refuse."""
    wire = c.act.wire
    reordered = json.dumps(dict(reversed(list(json.loads(wire).items())))).encode()
    variants = [wire + b"\n", b" " + wire, wire.replace(b'":', b'": ', 1), reordered]
    alt = c.rng.choice([v for v in variants if v != wire])
    status, code = c.w.present(c.act.permit, alt)
    held = status == 403 and code == "RECEIVER_WIRE_MISMATCH"
    return (
        ("CAUGHT" if held else "LAYER_MISS"),
        f"{len(alt)}B vs {len(wire)}B: gate={status}:{code}",
        0,
    )


def permit_forged(c: Ctx) -> Result:
    header = c.act.permit.header
    i = c.rng.randrange(len(header) // 3, 2 * len(header) // 3)
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    forged = (
        header[:i] + c.rng.choice(alphabet.replace(header[i], "")) + header[i + 1 :]
    )
    status, payload = c.w.p.present(forged, c.act.wire)
    held = status in (400, 401, 403)
    return (
        ("CAUGHT" if held else "LAYER_MISS"),
        f"char {i} changed: gate={status}:{payload.get('reason_code')}",
        0,
    )


def permit_swapped(c: Ctx) -> Result:
    d = next(c.decoys)
    other = c.w.arguments(d.order_id, d.amount, d.payee)
    status, code = c.w.present(c.act.permit, _m().wire_for(other))
    held = status == 403 and code == "RECEIVER_WIRE_MISMATCH"
    return (
        ("CAUGHT" if held else "LAYER_MISS"),
        f"on {other['refund_id']}: gate={status}:{code}",
        0,
    )


def no_permit(c: Ctx) -> Result:
    r = c.w.p.gate_client.post(
        _m().cfg.REFUNDS_PATH,
        content=c.act.wire,
        headers={"Content-Type": "application/json"},
    )
    return (
        ("CAUGHT" if r.status_code == 403 else "LAYER_MISS"),
        f"gate={r.status_code}",
        0,
    )


def remint_tampered(c: Ctx) -> Result:
    atk = _m()
    tampered = _mutate(c.act.args, amount=c.act.args["amount"] + c.rng.randint(1, 5000))
    wire = atk.wire_for(tampered)
    body = dict(c.act.permit.body)
    body.update(
        action=c.w.p.tool.execution_action(
            atk.cfg.AGENT_ID, atk.cfg.ORGANISATION_ID, tampered
        ),
        expected_wire_bytes_digest=atk.sha256_bytes_digest(wire),
        expected_wire_bytes_length=len(wire),
    )
    status, payload = c.w.authorize(body)
    detail = payload.get("detail")
    code = (
        detail.get("reason_code")
        if isinstance(detail, dict)
        else payload.get("reason_code")
    )
    if status == 200:  # a permit now exists for bytes nobody decided
        return "ESCAPED", f"/v1/authorize minted for {tampered['amount']}", 0
    return "CAUGHT", f"/v1/authorize for {tampered['amount']}: {status}:{code}", 0


def _decide_and_spend(
    c: Ctx, args: dict[str, Any], what: str, expect: str, **kw: Any
) -> Result:
    """A lie or a stolen approval must BLOCK at decide. If it is allowed,
    spend it as an attacker would; the ledger then decides ESCAPED."""
    atk = _m()
    out = c.w.p.pv.decide(c.w.p.tool, args, **kw)
    if not out.allowed:
        named = expect in f"{out.reason} {out.triggered_by}"
        verdict = "CAUGHT" if out.decision == "block" and named else "LAYER_MISS"
        if expect == "" and out.decision in ("block", "require_approval"):
            verdict = "CAUGHT"
        return verdict, f"{what} -> {_reason(out)}", 0
    try:
        permit = c.w.p.pv.mint(out, c.w.p.tool, args)
        status, code = c.w.present(permit, atk.wire_for(args))
        spent = f"minted, gate={status}:{code}"
    except atk.GateError as exc:
        spent = f"mint refused: {exc}"
    return "LAYER_MISS", f"{what} -> ALLOWED, {spent}", 0


def facts_overpay(c: Ctx) -> Result:
    """Claim 11: a compromised tool inflates the order to cover an overpay."""
    d = next(c.decoys)
    honest = c.w.arguments(d.order_id, d.amount, d.payee)
    true = honest["original_amount"]
    claim = min(true * c.rng.choice([2, 3]), 19000)
    lie = dict(
        _mutate(honest, amount=claim),
        original_amount=claim,
        amount_exceeds_original=False,
    )
    return _decide_and_spend(
        c, lie, f"{d.order_id} says original {claim}, record {true}", "FACTS_MISMATCH"
    )


def facts_identity(c: Ctx) -> Result:
    """Claim 11, with teeth: right after the velocity race the customer is at
    the daily limit. Their sixth order is asked for under another customer's
    name, with a clean history. If the lie passes, the ledger shows a fourth
    refund for a customer the policy caps at three."""
    if not c.probe:
        return "CAUGHT", "skipped: no customer at the limit this cycle", 0
    o = c.probe[5]
    honest = c.w.arguments(o.order_id, o.amount, o.payee)
    lie = dict(
        honest,
        customer_id="C-0001",
        customer_refunds_today=0,
        customer_amount_today_after=honest["amount"],
    )
    verdict, detail, _ = _decide_and_spend(
        c,
        lie,
        f"{o.customer_id} at the limit, {o.order_id} as C-0001",
        "FACTS_MISMATCH",
    )
    ids = {p.order_id for p in c.probe}
    paid = sum(1 for r in c.w.ledger() if r.get("order_id") in ids)
    if paid > VELOCITY_LIMIT:
        return "ESCAPED", f"{detail}; {o.customer_id} now has {paid} refunds today", 1
    return verdict, detail, 0


def approval_other_order(c: Ctx) -> Result:
    """A human approval for one refund, offered to another that needs one."""
    d = next(c.big_decoys)
    other = c.w.arguments(d.order_id, d.amount, d.payee)
    return _decide_and_spend(
        c,
        other,
        f"approval of {c.act.refund_id} on {d.order_id}",
        "",
        approval=c.act.approval,
    )


def approval_amount_raised(c: Ctx) -> Result:
    raised = _mutate(c.act.args, amount=c.act.args["amount"] + 1000)
    return _decide_and_spend(
        c,
        raised,
        f"approved {c.act.args['amount']}, asks {raised['amount']}",
        "",
        approval=c.act.approval,
    )


def honest_send(c: Ctx) -> Result:
    res = c.w.p.pv.dispatch(c.act.permit, c.w.p.tool, c.act.args)
    return (
        ("PAID" if res.outcome == "EXECUTED" else "DENIED"),
        f"sidecar={res.outcome}",
        1,
    )


def first_use_race(c: Ctx) -> Result:
    """The honest send, as eight simultaneous first uses of one permit."""
    with ThreadPoolExecutor(8) as pool:
        codes = Counter(
            s
            for s, _ in pool.map(
                lambda _: c.w.present(c.act.permit, c.act.wire), range(8)
            )
        )
    won = codes.get(201, 0)
    verdict = "PAID" if won == 1 else ("DENIED" if won == 0 else "ESCAPED")
    return verdict, f"8 at once: {dict(codes)}", 1


def replay_serial(c: Ctx) -> Result:
    codes = Counter(c.w.present(c.act.permit, c.act.wire)[0] for _ in range(3))
    return ("CAUGHT" if 201 not in codes else "ESCAPED"), f"3 replays: {dict(codes)}", 0


def replay_burst(c: Ctx) -> Result:
    with ThreadPoolExecutor(8) as pool:
        codes = Counter(
            s
            for s, _ in pool.map(
                lambda _: c.w.present(c.act.permit, c.act.wire), range(8)
            )
        )
    return (
        ("CAUGHT" if 201 not in codes else "ESCAPED"),
        f"8 concurrent replays: {dict(codes)}",
        0,
    )


def sidecar_retry(c: Ctx) -> Result:
    """A caller that lost the answer and retries through the sidecar."""
    res = c.w.p.pv.dispatch(c.act.permit, c.w.p.tool, c.act.args)
    return "CAUGHT", f"retry: sidecar={res.outcome} (the ledger judges)", 0


def redecide(c: Ctx) -> Result:
    """The agent asks for the same refund again, with fresh true facts."""
    o = c.act.order
    again = c.w.arguments(o.order_id, o.amount, o.payee)
    return _decide_and_spend(
        c,
        again,
        f"second {again['refund_id']} for {o.order_id}",
        "already has a refund",
    )


def stale_facts(c: Ctx) -> Result:
    """The spent action's own arguments, replayed: they still say 'no prior
    refunds', which the system of record now contradicts."""
    return _decide_and_spend(
        c,
        dict(c.act.args),
        f"{c.act.refund_id} with pre-payment facts",
        "FACTS_MISMATCH",
    )


def velocity_race(c: Ctx) -> Result:
    """Claim 10: five refunds for one customer decided at once. The tool's
    count is stale for all five; only the server's atomic counter can hold."""
    atk = _m()
    c.probe = next(c.probes)
    orders = c.probe[:5]
    args = [c.w.arguments(o.order_id, o.amount, o.payee) for o in orders]

    def go(a: dict[str, Any]) -> str:
        out = c.w.p.pv.decide(c.w.p.tool, a)
        if not out.allowed:
            return f"{out.decision}:{out.triggered_by}"
        try:
            permit = c.w.p.pv.mint(out, c.w.p.tool, a)
            return f"gate:{c.w.present(permit, atk.wire_for(a))[0]}"
        except atk.GateError:
            return "mint-refused"

    with ThreadPoolExecutor(5) as pool:
        seen = Counter(pool.map(go, args))
    ids = {o.order_id for o in orders}
    rows = [r for r in c.w.ledger() if r.get("order_id") in ids]
    paid, c.race_paid = len(rows), sum(int(r["amount"]) for r in rows)
    verdict = "CAUGHT" if paid <= VELOCITY_LIMIT else "ESCAPED"
    return (
        verdict,
        f"{orders[0].customer_id}: {dict(seen)}; paid {paid} (limit {VELOCITY_LIMIT})",
        min(paid, VELOCITY_LIMIT),
    )


def upstream_direct(c: Ctx) -> Result:
    """Claim 16 and an oracle self-check: a refund posted straight to the
    payments API. In the demo the mock pays it (documented); reconciliation
    must then find a payment with no receipt, or the oracle is blind."""
    atk = _m()
    d = next(c.decoys)
    rid = f"RF-BYPASS-{c.act.seq}"
    body = atk.wire_for(
        dict(c.w.arguments(d.order_id, d.amount, d.payee), refund_id=rid)
    )
    req = urllib.request.Request(
        c.w.url("payments") + atk.cfg.REFUNDS_PATH,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            code = r.status
    except urllib.error.HTTPError as exc:
        code = exc.code
    if code != 201:
        return "CAUGHT", f"upstream refused a request that skipped the gate: {code}", 0
    flagged = {
        r.get("refund_id") for r in atk.reconcile(c.w)["payments_without_receipt"]
    }
    if rid in flagged:
        return "BOUNDARY", f"{rid} paid without the gate; reconciliation flagged it", 1
    return "BLIND", f"{rid} paid without the gate and reconciliation did not flag it", 1


def receipts_drill(c: Ctx) -> Result:
    """Claim 5: the receipt chain verifies, and one changed byte fails it."""
    rep = _m().verify_receipts(c.w.run_dir, c.w.run_dir / "gate" / "receiver.db")
    brief = {
        k: v
        for k, v in rep.items()
        if isinstance(v, bool | int | str) and len(str(v)) < 40
    }
    return ("CAUGHT" if rep.get("ok") else "BLIND"), f"verifier: {brief}", 0


def reconcile_check(c: Ctx) -> Result:
    r = _m().reconcile(c.w)
    stray = [
        p
        for p in r["payments_without_receipt"]
        if not str(p.get("refund_id", "")).startswith("RF-BYPASS-")
    ]
    detail = (
        f"payments={r['payments']} receipts={r['admitted_receipts']} unreceipted={len(stray)} "
        f"receipt-without-payment={len(r['receipts_without_payment'])} "
        f"overpaid={len(r['paid_more_often_than_admitted'])}"
    )
    if stray or r["paid_more_often_than_admitted"]:
        return "ESCAPED", detail, 0
    return ("DENIED" if r["receipts_without_payment"] else "CAUGHT"), detail, 0


PRE: list[Callable[[Ctx], Result]] = [
    amount_changed,
    payee_changed,
    byte_smuggled,
    permit_forged,
    permit_swapped,
    no_permit,
    remint_tampered,
    facts_overpay,
]
PRE_APPROVED = [approval_other_order, approval_amount_raised]
POST = [replay_serial, replay_burst, sidecar_retry, redecide, stale_facts]


# ------------------------------------------------------------------ driver
class Challenger:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.rng = random.Random(args.seed)
        self.root = Path(args.run_dir).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.log = (self.root / "challenger.jsonl").open("a", encoding="utf-8")
        self.tally: dict[str, Counter[str]] = defaultdict(Counter)
        self.failures: list[dict[str, Any]] = []
        self.known: Counter[str] = Counter()
        self.actions = 0
        self.epoch = 0

    # one challenge, judged by the ledger
    def run_one(self, fn: Callable[[Ctx], Result], c: Ctx) -> str:
        name = fn.__name__.replace("reconcile_check", "reconcile")
        before = len(c.w.ledger())
        t0 = time.perf_counter()
        try:
            verdict, detail, may_add = fn(c)
        except StopIteration:
            raise
        except Exception as exc:  # a challenge that cannot run has not passed
            verdict, detail, may_add = "ERROR", f"{type(exc).__name__}: {exc}", 0
        added = len(c.w.ledger()) - before
        if added > may_add:
            verdict, detail = (
                "ESCAPED",
                f"{detail} | ledger +{added}, allowed +{may_add}",
            )
        elif verdict == "PAID" and added < may_add:
            verdict, detail = "DENIED", f"{detail} | nothing reached the ledger"
        self.record(c.act, name, verdict, detail, added, time.perf_counter() - t0)
        return verdict

    def record(
        self,
        act: Approved | None,
        name: str,
        verdict: str,
        detail: str,
        added: int,
        secs: float,
    ) -> None:
        row = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "epoch": self.epoch,
            "seq": act.seq if act else None,
            "refund_id": act.refund_id if act else None,
            "challenge": name,
            "claims": CLAIMS.get(name, ""),
            "verdict": verdict,
            "detail": detail,
            "ledger_added": added,
            "ms": round(secs * 1000, 1),
        }
        self.log.write(json.dumps(row) + "\n")
        self.log.flush()
        self.tally[name][verdict] += 1
        failing = verdict in FAILING or (
            verdict == "BOUNDARY" and self.args.boundary_closed
        )
        if failing and {verdict, f"{verdict}:{name}"} & set(self.args.known):
            self.known[f"{verdict}:{name}"] += 1
        elif failing:
            self.failures.append(row)
            print(f"   !! {verdict:<10} {name:<22} {detail}", flush=True)
        elif self.args.verbose:
            print(f"      {verdict:<10} {name:<22} {detail}", flush=True)

    def obtain(self, w: Any, o: Order, seq: int) -> Approved:
        """The agent's proposal, decided like any other: approval if asked."""
        atk = _m()
        a = w.arguments(o.order_id, o.amount, o.payee)
        rid = w.p.pv.new_request_id()
        out = w.p.pv.decide(w.p.tool, a, request_id=rid)
        approval = None
        if out.decision == "require_approval":
            wire = atk.wire_for(a)
            w.inbox.submit(
                request_id=rid,
                action=w.p.tool.execution_action(
                    atk.cfg.AGENT_ID, atk.cfg.ORGANISATION_ID, a
                ),
                reason=out.reason,
                wire_digest=atk.sha256_bytes_digest(wire),
                wire_length=len(wire),
                context={"request": seq, "challenger": True},
            )
            approval = (w.inbox.wait(rid, timeout_s=60) or {}).get("approval")
            if approval is None:
                raise NoHonestPathError(f"no approval arrived for {a['refund_id']}")
            out = w.p.pv.decide(w.p.tool, a, approval=approval, request_id=rid)
        if not out.allowed:
            raise NoHonestPathError(f"{a['refund_id']} {a['amount']}: {_reason(out)}")
        permit = w.p.pv.mint(out, w.p.tool, a)
        return Approved(seq, o, a, atk.wire_for(a), permit, approval)

    @staticmethod
    def spent(w: Any) -> int:
        """What the refund grant has been charged, read from the lab copy of
        the server's ledger (read-only)."""
        db = w.run_dir / "privatevault" / "pv.db"
        try:
            con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
            try:
                row = con.execute(
                    "select coalesce(sum(cast(spent as real)), 0) from grant_spend"
                ).fetchone()
            finally:
                con.close()
        except sqlite3.Error:
            return 0
        return round(row[0])

    def cycle(
        self, w: Any, book: Book, its: dict[str, Iterator[Any]], seq: int
    ) -> None:
        o = next(its["honest"])
        charged_before = self.spent(w)
        try:
            act = self.obtain(w, o, seq)
        except NoHonestPathError as exc:
            self.record(None, "honest_decide", "DENIED", str(exc), 0, 0.0)
            return
        c = Ctx(w, self.rng, act, its["decoys"], its["big"], its["probes"])
        pre = PRE + (PRE_APPROVED if act.approval else [])
        verdicts = [self.run_one(fn, c) for fn in self.rng.sample(pre, len(pre))]
        send = first_use_race if self.rng.random() < 0.3 else honest_send
        verdicts.append(self.run_one(send, c))
        verdicts += [self.run_one(fn, c) for fn in self.rng.sample(POST, len(POST))]
        money = self.money_oracle(c)
        verdicts.append(money)
        every = self.args
        if seq % every.race_every == 0:
            verdicts.append(self.run_one(velocity_race, c))
            verdicts.append(self.run_one(facts_identity, c))
        if seq % every.bypass_every == 0:
            verdicts.append(self.run_one(upstream_direct, c))
        if seq % every.reconcile_every == 0:
            verdicts.append(self.run_one(reconcile_check, c))
        if seq % every.drill_every == 0:
            verdicts.append(self.run_one(receipts_drill, c))
        verdicts.append(self.budget_oracle(c, charged_before, money))
        self.actions += 1
        caught = sum(v in ("CAUGHT", "PAID", "BOUNDARY") for v in verdicts)
        mark = "ok" if caught == len(verdicts) else "FINDINGS"
        kind = "approved" if act.approval else "allow"
        print(
            f"#{seq:04d} {act.refund_id:<14} Rs {act.args['amount']:>6,} {kind:<8} "
            f"{caught}/{len(verdicts)} held  {mark}",
            flush=True,
        )

    def money_oracle(self, c: Ctx) -> str:
        """After every challenge on this action: paid once, as decided."""
        rows = [r for r in c.w.ledger() if r.get("order_id") == c.act.order.order_id]
        amounts = [int(r["amount"]) for r in rows]
        if amounts == [c.act.args["amount"]]:
            verdict = "CAUGHT"
        elif not amounts:
            verdict = "DENIED"
        else:
            verdict = "ESCAPED"
        self.record(
            c.act,
            "money_oracle",
            verdict,
            f"{c.act.order.order_id} paid {amounts}, decided [{c.act.args['amount']}]",
            0,
            0.0,
        )
        return verdict

    def budget_oracle(self, c: Ctx, before: int, money: str) -> str:
        """The grant pays for money moved without a human, nothing else:
        refused decides and lies must not spend it."""
        unattended = (
            c.act.args["amount"] if c.act.approval is None and money == "CAUGHT" else 0
        )
        expected = unattended + c.race_paid
        charged = self.spent(c.w) - before
        verdict = "CAUGHT" if charged == expected else "LEAK"
        detail = f"grant charged Rs {charged:,}; paid without approval Rs {expected:,}"
        if charged != expected:
            detail += f"; leaked Rs {charged - expected:,}"
        self.record(c.act, "budget_oracle", verdict, detail, 0, 0.0)
        return verdict

    def done(self, started: float) -> bool:
        a = self.args
        if a.stop_on_failure and self.failures:
            return True
        if a.actions and self.actions >= a.actions:
            return True
        return bool(a.minutes and time.monotonic() - started >= a.minutes * 60)

    def run(self) -> int:
        atk = _m()
        queue = Path(os.environ[QUEUE_ENV])
        shipped, atk.cfg.QUEUE_FILE = atk.cfg.QUEUE_FILE, queue
        try:
            return self._epochs(atk, queue)
        finally:
            atk.cfg.QUEUE_FILE = shipped
            self.log.close()

    def _epochs(self, atk: Any, queue: Path) -> int:
        started = time.monotonic()
        seq = 0
        while not self.done(started):
            self.epoch += 1
            run_dir = self.root / f"epoch-{self.epoch:03d}"
            book = build_book(queue, self.rng, self.args.book_scale)
            w = atk.start_world(run_dir)
            its: dict[str, Iterator[Any]] = {
                "honest": iter(book.honest),
                "decoys": iter(book.decoys),
                "big": iter(book.big_decoys),
                "probes": iter(book.probes),
            }
            print(f"-- epoch {self.epoch}: services up in {run_dir}", flush=True)
            try:
                while not self.done(started):
                    seq += 1
                    try:
                        self.cycle(w, book, its, seq)
                    except StopIteration:
                        break  # this epoch's order book is spent: a fresh world
            finally:
                atk.stop_world(w)
        return self.summary(started)

    def summary(self, started: float) -> int:
        secs = time.monotonic() - started
        total = sum(sum(t.values()) for t in self.tally.values())
        print(
            f"\n{self.actions} approved actions challenged, {total} checks, {secs:.0f}s, {self.epoch} epoch(s)"
        )
        print(
            f"{'challenge':<22} {'claims':<8} "
            + "  ".join(f"{v:<8}" for v in ("CAUGHT", "PAID", "BOUNDARY", "failing"))
        )
        for name in sorted(self.tally):
            t = self.tally[name]
            bad = sum(n for v, n in t.items() if v in FAILING)
            print(
                f"{name:<22} {CLAIMS.get(name, ''):<8} {t['CAUGHT']:<8}  {t['PAID']:<8}  {t['BOUNDARY']:<8}  {bad}"
            )
        report = {
            "actions": self.actions,
            "checks": total,
            "seconds": round(secs, 1),
            "tally": {k: dict(v) for k, v in self.tally.items()},
            "failures": self.failures,
            "known": dict(self.known),
            "seed": self.args.seed,
        }
        (self.root / "challenger-summary.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8"
        )
        for key, n in sorted(self.known.items()):
            print(f"known (accepted, not failing): {key} x{n}")
        print(
            f"\n{len(self.failures)} failing verdict(s). Log: {self.root / 'challenger.jsonl'}"
        )
        return 1 if self.failures else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--minutes", type=float, default=0, help="stop after this long")
    p.add_argument(
        "--actions", type=int, default=0, help="stop after this many approved actions"
    )
    p.add_argument("--forever", action="store_true", help="run until interrupted")
    p.add_argument("--seed", type=int, default=None, help="replay a run exactly")
    p.add_argument("--run-dir", default=str(HERE / ".challenger"))
    p.add_argument("--race-every", type=int, default=6)
    p.add_argument("--bypass-every", type=int, default=10)
    p.add_argument("--reconcile-every", type=int, default=5)
    p.add_argument("--drill-every", type=int, default=15)
    p.add_argument(
        "--book-scale", type=float, default=1.0, help="orders per epoch, relative"
    )
    p.add_argument("--stop-on-failure", action="store_true")
    p.add_argument(
        "--known",
        action="append",
        default=[],
        metavar="VERDICT[:challenge]",
        help="an accepted finding while its fix lands: logged, not failing",
    )
    p.add_argument(
        "--boundary-closed",
        action="store_true",
        help="a payment that skipped the gate fails the run",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="print every verdict")
    args = p.parse_args(argv)
    if not (args.minutes or args.actions or args.forever):
        args.actions = 20
    if args.seed is None:
        args.seed = random.SystemRandom().randrange(10**6)
    run_dir = Path(args.run_dir).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    previous = os.environ.get(QUEUE_ENV)
    os.environ[QUEUE_ENV] = str(run_dir / "order_book.json")  # before the demo imports
    print(f"challenger seed={args.seed} (replay with --seed {args.seed})", flush=True)
    try:
        return Challenger(args).run()
    except KeyboardInterrupt:
        return 130
    finally:  # leave the environment as found: later worlds use the shipped book
        if previous is None:
            os.environ.pop(QUEUE_ENV, None)
        else:
            os.environ[QUEUE_ENV] = previous


if __name__ == "__main__":
    raise SystemExit(main())
