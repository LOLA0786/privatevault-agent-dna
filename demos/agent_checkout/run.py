"""Agent checkout demo: one order, four attacks, one gate.

    uv run python demos/agent_checkout/run.py            # paced, about 3 minutes
    uv run python demos/agent_checkout/run.py --fast     # no pauses
    uv run python demos/agent_checkout/run.py --manual   # press Enter between steps

A procurement agent creates a payment-gateway order of 18,500 INR to
merchant M-1021 through PrivateVault. Then the attacks: a prompt injection
changes the amount after approval, the payee is swapped, the used permit is
replayed, and a request over the hard cap is tried with an approval in hand.
The receiver gate in front of the mock checkout API refuses all of them.
Receipts are exported and verified independently, and the same requests
are run against the bare API for a side-by-side.

Writes ``report.html`` next to this file. Exit status 0 only if every check
holds. No network beyond loopback, no real keys, scripted model.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import logging
import os
import shutil
import sys
import tempfile
import textwrap
import time
import webbrowser
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # run as a script

from demos.agent_checkout.report import write_report  # noqa: E402
from demos.agent_checkout.scenario import (  # noqa: E402
    Event,
    ScenarioResult,
    run_scenario,
)

HERE = Path(__file__).resolve().parent
REPORT = HERE / "report.html"
TOTAL_STEPS = 9
WIDTH = 78


# ------------------------------------------------------------------ colour


class Paint:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, t: str) -> str:
        return self._wrap("1", t)

    def dim(self, t: str) -> str:
        return self._wrap("2", t)

    def green(self, t: str) -> str:
        return self._wrap("32", t)

    def red(self, t: str) -> str:
        return self._wrap("31", t)

    def yellow(self, t: str) -> str:
        return self._wrap("33", t)

    def blue(self, t: str) -> str:
        return self._wrap("34", t)

    def cyan(self, t: str) -> str:
        return self._wrap("36", t)

    def magenta(self, t: str) -> str:
        return self._wrap("35", t)


def inr(amount: Any) -> str:
    """Indian grouping: 2,50,000."""
    n = int(amount)
    s = str(abs(n))
    if len(s) <= 3:
        return ("-" if n < 0 else "") + "₹" + s
    head, tail = s[:-3], s[-3:]
    parts: list[str] = []
    while len(head) > 2:
        parts.insert(0, head[-2:])
        head = head[:-2]
    if head:
        parts.insert(0, head)
    return ("-" if n < 0 else "") + "₹" + ",".join(parts) + "," + tail


def short(value: Any, keep: int = 24) -> str:
    text = "-" if value is None else str(value)
    return text if len(text) <= keep + 1 else text[:keep] + "…"


# --------------------------------------------------------------- presenter


class Presenter:
    def __init__(self, paint: Paint, pause: float, manual: bool) -> None:
        self.p = paint
        self.pause = pause
        self.manual = manual
        self.started = time.monotonic()

    # ---- primitives
    def line(self, text: str = "") -> None:
        print(text, flush=True)

    def wrap(self, text: str, indent: str = "   ") -> None:
        for chunk in textwrap.wrap(text, WIDTH - len(indent)):
            self.line(indent + self.p.dim(chunk))

    def kv(self, key: str, value: str) -> None:
        self.line(f"   {self.p.dim(key.ljust(11))} {value}")

    def rule(self, title: str = "", number: int | None = None) -> None:
        p = self.p
        tag = f" Step {number} of {TOTAL_STEPS} " if number else " "
        head = f"━━{tag}─ {title} "
        pad = max(2, WIDTH - len(head))
        self.line("")
        self.line(p.bold(p.cyan(head + "━" * pad)))

    def wait(self) -> None:
        if self.manual:
            try:
                input(self.p.dim("   ↵ press Enter for the next step "))
            except EOFError:
                pass
            return
        if self.pause > 0:
            time.sleep(self.pause)

    # ---- outcome words
    def admitted(self, text: str) -> str:
        return self.p.bold(self.p.green("ADMITTED  ")) + text

    def refused(self, text: str) -> str:
        return self.p.bold(self.p.red("REFUSED   ")) + text

    def blocked(self, text: str) -> str:
        return self.p.bold(self.p.red("BLOCK     ")) + text

    def checks(self, event: Event) -> None:
        for c in event.checks:
            mark = self.p.green("✔") if c.ok else self.p.red("✘ FAIL")
            self.line(f"   {mark} {c.label}")

    def request(self, req: dict[str, Any] | None) -> None:
        if not req:
            return
        self.kv(
            "order",
            f"{req.get('order_id')}  {self.p.bold(inr(req.get('amount', 0)))} {req.get('currency')}"
            f"  → merchant {self.p.bold(str(req.get('merchant_id')))}",
        )

    # ---- intro and outro
    def intro(self, run_dir: Path) -> None:
        p = self.p
        self.line("")
        self.line(p.bold("PrivateVault · agent checkout demo"))
        self.line(
            p.dim(
                "One procurement agent, one payment-gateway order API, one receiver gate between them."
            )
        )
        self.line(p.dim(f"Run directory: {run_dir}"))
        self.line("")
        self.line(
            "   "
            + p.cyan("agent")
            + "  →  "
            + p.blue("PrivateVault decide / approve / mint")
            + "  →  "
            + p.blue("sidecar")
            + "  →  "
            + p.magenta("receiver gate")
            + "  →  "
            + p.dim("checkout API (mock)")
        )
        self.line(
            p.dim(
                "   policy: approval above ₹10,000 · hard cap ₹2,00,000 · currency INR"
            )
        )
        self.wait()

    # ---- per-event renderers
    def show(self, event: Event) -> None:  # noqa: C901 - one branch per step
        p = self.p
        self.rule(event.title, event.number)
        self.wrap(event.narrative)
        self.line("")
        d = event.detail or {}
        if event.key == "order":
            cart = d.get("cart") or {}
            self.kv(
                "cart",
                f"{cart.get('cart_id')}  {len(cart.get('items', []))} line item(s)",
            )
            self.request(event.request)
            self.kv(
                "holds",
                p.dim(
                    "no credentials, no gateway access; the proposal is bytes, not power"
                ),
            )
        elif event.key == "decide":
            self.kv(
                "decide #1",
                p.yellow("REQUIRE_APPROVAL") + p.dim(f"  policy {event.policy_id}"),
            )
            self.kv("reason", p.dim(short(event.reason, 64)))
            self.kv("approver", f"{event.approver}  signs for exactly this action")
            self.kv("approval", short(event.approval_digest, 40))
            self.kv(
                "decide #2",
                p.green("ALLOW")
                + p.dim(
                    f"  triggered_by={event.triggered_by}  decision {short(event.decision_id, 20)}"
                ),
            )
            self.kv("permit", p.bold(str(event.permit_id)) + p.dim("  single-use"))
            b = event.permit_bound_to or {}
            self.kv(
                "bound to",
                f"bytes {short(b.get('wire_bytes_digest'), 30)} ({b.get('wire_bytes_length')} B)",
            )
            self.kv(
                "", f"action {short(b.get('action_digest'), 30)}  {b.get('operation')}"
            )
            self.kv("", f"approval {short(b.get('approval_artifact_digest'), 30)}")
        elif event.key == "gate_admit":
            self.kv(
                "sidecar",
                self.admitted(
                    p.dim(f"outcome={event.sidecar_outcome}, bytes sent once")
                ),
            )
            self.kv(
                "gate",
                self.admitted(
                    p.dim(
                        f"HTTP {event.gate_status}  receipt #{event.receipt_sequence} {short(event.receipt_digest, 30)}"
                    )
                ),
            )
            api = event.api_response or {}
            self.kv(
                "api",
                p.green(f"HTTP 201 {api.get('status')}")
                + p.dim(f"  {api.get('gateway_ref')}  orders={event.api_orders_after}"),
            )
        elif event.key in ("attack_amount", "attack_payee"):
            if d.get("injected_note"):
                self.kv("injected", p.yellow("“" + short(d["injected_note"], 66) + "”"))
            self.request(event.request)
            self.kv(
                "permit", p.dim(f"{event.permit_id} (minted for the approved bytes)")
            )
            self.kv(
                "sidecar",
                self.refused(p.dim(f"{event.sidecar_reason}, before any byte")),
            )
            self.kv(
                "gate",
                self.refused(
                    p.dim(
                        f"HTTP {event.gate_status} {event.gate_reason}  (sidecar bypassed)  receipt #{event.receipt_sequence}"
                    )
                ),
            )
            self.kv(
                "api",
                p.green("never reached")
                + p.dim(f"  orders still {event.api_orders_after}"),
            )
        elif event.key == "attack_replay":
            self.request(event.request)
            self.kv("permit", p.dim(f"{event.permit_id} (already consumed)"))
            self.kv(
                "gate",
                self.refused(
                    p.dim(
                        f"HTTP {event.gate_status} {event.gate_reason}  receipt #{event.receipt_sequence}"
                    )
                ),
            )
            self.kv(
                "api",
                p.green("never reached")
                + p.dim(f"  orders still {event.api_orders_after}"),
            )
        elif event.key == "hard_cap":
            self.request(event.request)
            self.kv(
                "decide",
                self.blocked(p.dim(f"policy {event.policy_id}: {event.reason}")),
            )
            self.kv(
                "w/ approval",
                self.blocked(
                    p.dim(
                        f"signed approval attached, decision still {d.get('with_approval_decision')} (HTTP {d.get('with_approval_status')})"
                    )
                ),
            )
            self.kv("permit", p.dim("none minted; BLOCK is not dispatchable"))
            self.kv(
                "api",
                p.green("never reached")
                + p.dim(f"  orders still {event.api_orders_after}"),
            )
        elif event.key == "receipts":
            self.kv("exported", f"{d.get('receipts')} receipts")
            self.kv(
                "gate key",
                f"{d.get('receiver_key_id')} = {short(d.get('receiver_public_key'), 44)}",
            )
            self.kv(
                "verifier",
                (p.green if event.ok else p.red)(
                    str(d.get("verifier", "")).splitlines()[0]
                    if d.get("verifier")
                    else "no output"
                ),
            )
        elif event.key == "comparison":
            self.table(d.get("rows", []))
        self.line("")
        self.checks(event)
        if event.number < TOTAL_STEPS:
            self.wait()

    def table(self, rows: list[dict[str, Any]]) -> None:
        p = self.p
        c1, c2, c3 = 36, 32, 36
        top = "   ┌" + "─" * c1 + "┬" + "─" * c2 + "┬" + "─" * c3 + "┐"
        mid = "   ├" + "─" * c1 + "┼" + "─" * c2 + "┼" + "─" * c3 + "┤"
        bot = "   └" + "─" * c1 + "┴" + "─" * c2 + "┴" + "─" * c3 + "┘"

        def cell(text: str, width: int, colour: Any = None) -> str:
            text = text if len(text) <= width - 2 else text[: width - 3] + "…"
            padded = " " + text.ljust(width - 1)
            return colour(padded) if colour else padded

        self.line(top)
        self.line(
            "   │"
            + cell("request", c1, p.bold)
            + "│"
            + cell("without PrivateVault", c2, p.bold)
            + "│"
            + cell("with PrivateVault", c3, p.bold)
            + "│"
        )
        self.line(mid)
        for r in rows:
            honest = r["attack"].startswith("Honest")
            left_colour = p.green if honest else p.red
            left_icon = "✔ " if honest else "✘ "
            self.line(
                "   │"
                + cell(r["attack"], c1)
                + "│"
                + cell(left_icon + r["without_pv"], c2, left_colour)
                + "│"
                + cell("✔ " + r["with_pv"], c3, p.green)
                + "│"
            )
        self.line(bot)
        self.line(
            p.dim(
                "   ✘ = the request became an order it should not have; ✔ = the intended outcome"
            )
        )

    def outro(self, result: ScenarioResult, report: Path) -> None:
        p = self.p
        elapsed = time.monotonic() - self.started
        self.line("")
        self.line(p.bold(p.cyan("━" * WIDTH)))
        if result.ok:
            self.line(p.bold(p.green("ALL CHECKS PASS")) + p.dim(f"   {elapsed:.0f}s"))
        else:
            failed = [c.label for e in result.events for c in e.checks if not c.ok]
            self.line(
                p.bold(p.red(f"{len(failed)} CHECK(S) FAILED"))
                + p.dim("  " + "; ".join(failed))
            )
        self.line(p.dim(f"report    {report}"))
        self.line(p.dim(f"receipts  {result.receipts_path}"))
        self.line(p.dim(f"timeline  {result.run_dir / 'timeline.json'}"))
        self.line("")


# -------------------------------------------------------------------- main


def _colour_enabled(flag: str) -> bool:
    if flag == "always":
        return True
    if flag == "never" or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--fast", action="store_true", help="no pauses between steps")
    parser.add_argument(
        "--manual", action="store_true", help="press Enter between steps"
    )
    parser.add_argument(
        "--pause", type=float, default=15.0, help="seconds between steps (default 15)"
    )
    parser.add_argument(
        "--run-dir", default=None, help="where keys, ledgers and receipts go"
    )
    parser.add_argument(
        "--report", default=str(REPORT), help="where to write report.html"
    )
    parser.add_argument(
        "--open", action="store_true", help="open the report in a browser"
    )
    parser.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    parser.add_argument(
        "--verbose", action="store_true", help="show runtime and server logs"
    )
    args = parser.parse_args(argv)

    paint = Paint(_colour_enabled(args.color))
    pause = 0.0 if args.fast else args.pause
    presenter = Presenter(paint, pause, args.manual and not args.fast)
    run_dir = (
        Path(args.run_dir)
        if args.run_dir
        else Path(tempfile.mkdtemp(prefix="pv-checkout-"))
    )
    report_path = Path(args.report)

    presenter.intro(run_dir)
    quiet: Any = contextlib.nullcontext()
    if not args.verbose:
        logging.disable(logging.CRITICAL)
        quiet = contextlib.redirect_stderr(io.StringIO())
    with quiet:
        result = run_scenario(run_dir, observer=presenter.show)
    written = write_report(result, report_path)
    # Keep a copy of the receipts next to the report so the verify command
    # in the report works from this directory too.
    with contextlib.suppress(OSError):
        shutil.copy(result.receipts_path, written.parent / result.receipts_path.name)
    presenter.outro(result, written)
    if args.open:
        webbrowser.open(written.resolve().as_uri())
    return 0 if result.ok else 1


if __name__ == "__main__":
    sys.exit(main())
