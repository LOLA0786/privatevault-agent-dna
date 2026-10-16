"""The treasury approver's terminal.

    uv run python demos/treasury/approve.py                      # watch and decide
    uv run python demos/treasury/approve.py --auto approve --once   # tests
    uv run python demos/treasury/approve.py --unpinned           # sign with a key the API does not trust (demo)

Shows each pending approval: agent, action, amount in USD, counterparty and
the beneficiary account on file, the day's aggregate to that vendor, the
order bytes digest and the action hash. ``approve`` signs an
``approval_v01`` artifact for exactly that action with the treasury
approver's own key; ``deny`` records a denial. The approval bridge refuses
an approval whose signer is the requesting agent, or whose key is not in
the pinned approver bundle; ``--unpinned`` demonstrates the second.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # run as a script

from agent_dna.authority_v01 import sha256_digest  # noqa: E402
from agents.core.approval import ApproverKit  # noqa: E402
from demos.live_checkout.approvals import ApprovalInbox, PendingApproval  # noqa: E402
from demos.live_checkout.approve import ask, decide  # noqa: E402
from demos.live_checkout.events import (  # noqa: E402
    BOLD,
    DIM,
    RESET,
    YELLOW,
    colour_enabled,
    log,
)
from demos.treasury import config as cfg  # noqa: E402
from demos.treasury.bootstrap import approver_from_secret  # noqa: E402


def usd(amount: object) -> str:
    try:
        return f"USD {int(str(amount)):,}"
    except (TypeError, ValueError):
        return str(amount)


def show(item: PendingApproval) -> None:
    c = colour_enabled()
    b, d, y, r = (BOLD, DIM, YELLOW, RESET) if c else ("", "", "", "")
    p = item.parameters
    print()
    print(
        f"{y}{b}APPROVAL REQUESTED{r}  {d}{item.submitted_at}  request {item.request_id}{r}"
    )
    print(f"  {d}reason{r}       {item.reason}")
    print(f"  {d}requester{r}    {item.action.get('subject_principal')}")
    print(
        f"  {d}action{r}       {item.action.get('action')}  on  {item.action.get('resource')}"
    )
    print(f"  {d}amount{r}       {b}{usd(p.get('amount_usd'))}{r}")
    if p.get("kind") == "payment":
        print(
            f"  {d}counterparty{r} {b}{p.get('counterparty_id')}{r}  {p.get('counterparty_name')}  account on file {p.get('beneficiary_account')}"
        )
        print(
            f"  {d}facts{r}        on master {p.get('counterparty_on_master')}  bank details verified {p.get('bank_details_verified')}"
            f"  vendor paid today incl. this {usd(p.get('vendor_paid_today_incl_usd'))}"
        )
    else:
        print(
            f"  {d}accounts{r}     {p.get('from_account')} → {p.get('to_account')}  {p.get('to_currency', '')}"
        )
    print(
        f"  {d}desk clock{r}   {p.get('desk_clock')}  business hours {p.get('within_business_hours')}  agent actions last hour {p.get('agent_payments_last_hour')}"
    )
    print(f"  {d}order bytes{r}  {item.wire_digest} ({item.wire_length} B)")
    print(f"  {d}action hash{r}  {sha256_digest(item.action)}")
    for label, key in (
        ("action #", "action"),
        ("context", "text"),
        ("claude", "claude_reason"),
        ("mode", "mode"),
    ):
        value = item.context.get(key)
        if value:
            print(f"  {d}{label:<12}{r} {value}")


def run(
    inbox: ApprovalInbox,
    kit: ApproverKit,
    *,
    auto: str | None,
    once: bool,
    poll_s: float,
) -> int:
    seen: set[str] = set()
    log(
        "approver",
        "READY",
        "",
        principal=kit.principal,
        key=kit.key_id,
        inbox=str(inbox.root),
    )
    while True:
        for item in inbox.pending():
            if item.request_id in seen:
                continue
            show(item)
            if auto is not None:
                verdict: bool | None = auto == "approve"
                print(f"  auto: {auto}")
            else:
                verdict = ask(item)
            seen.add(item.request_id)
            if verdict is None:
                continue
            decide(inbox, kit, item, verdict)
            if once:
                return 0
        time.sleep(poll_s)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-dir", default=None)
    parser.add_argument("--auto", choices=["approve", "deny"], default=None)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--poll", type=float, default=0.5)
    parser.add_argument(
        "--unpinned",
        action="store_true",
        help="sign with the unpinned ap-clerk key (the API must refuse it)",
    )
    args = parser.parse_args(argv)
    run_dir = Path(args.run_dir) if args.run_dir else cfg.run_dir()
    secret_file = (
        run_dir / "approver" / ("unpinned.json" if args.unpinned else "secret.json")
    )
    if not secret_file.exists():
        print(
            f"no approver key at {secret_file}; run bootstrap.py first", file=sys.stderr
        )
        return 2
    kit = approver_from_secret(secret_file)
    try:
        return run(
            ApprovalInbox(run_dir / "approvals"),
            kit,
            auto=args.auto,
            once=args.once,
            poll_s=args.poll,
        )
    except KeyboardInterrupt:
        print()
        return 0


if __name__ == "__main__":
    sys.exit(main())
