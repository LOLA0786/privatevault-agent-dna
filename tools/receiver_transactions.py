"""List and reconcile business transaction claims in a receiver ledger (ADR 0030).

A claim that is CLAIMED (admitted, no upstream answer recorded: the gate
crashed or is still waiting) or INDETERMINATE (the upstream failed, timed
out or answered ambiguously) blocks its transaction key. Check the system
of record, then record what it says:

    python tools/receiver_transactions.py --ledger receiver.db list --open
    python tools/receiver_transactions.py --ledger receiver.db history \\
        --org lender.example --operation "POST /api/v1/transfers" --key INV-1001
    python tools/receiver_transactions.py --ledger receiver.db resolve \\
        --org lender.example --operation "POST /api/v1/transfers" --key INV-1001 \\
        --as not-executed --by "ops: a.kumar" --note "no posting in core banking"

``--as executed`` keeps the key refused for good; ``--as not-executed``
lets a new permit claim it. Each reconciliation is appended to the
ledger's event history with who and why. Run it on the receiver host while
the gate is running or stopped: the ledger serialises writers.

Exit status: 0 on success; 1 for ``list --open`` when anything is open (for
monitoring); 2 on a refused reconciliation or bad arguments.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent_dna.receiver.ledger import (  # noqa: E402
    ReceiverLedger,
    TransactionStateError,
)
from agent_dna.receiver.transactions import EXECUTED, NOT_EXECUTED  # noqa: E402

_AS = {"executed": EXECUTED, "not-executed": NOT_EXECUTED}


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ledger", required=True, type=Path)
    sub = parser.add_subparsers(dest="command", required=True)
    listing = sub.add_parser("list", help="transaction claims, oldest first")
    listing.add_argument(
        "--open", action="store_true", help="only CLAIMED/INDETERMINATE"
    )
    for name in ("history", "resolve"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--org", required=True)
        cmd.add_argument("--operation", required=True)
        cmd.add_argument("--key", required=True)
        if name == "resolve":
            cmd.add_argument(
                "--as", dest="resolution", required=True, choices=sorted(_AS)
            )
            cmd.add_argument(
                "--by", required=True, help="who checked the system of record"
            )
            cmd.add_argument(
                "--note", required=True, help="what the system of record shows"
            )
    args = parser.parse_args(argv)
    if not args.ledger.is_file():
        print(f"no ledger at {args.ledger}", file=sys.stderr)
        return 2
    ledger = ReceiverLedger(args.ledger)
    if args.command == "list":
        rows = ledger.transactions(open_only=args.open)
        for row in rows:
            print(json.dumps(row, sort_keys=True))
        return 1 if args.open and rows else 0
    if args.command == "history":
        for event in ledger.transaction_events(args.org, args.operation, args.key):
            print(json.dumps(event, sort_keys=True))
        return 0
    try:
        previous = ledger.resolve_transaction(
            args.org,
            args.operation,
            args.key,
            resolution=_AS[args.resolution],
            actor=args.by,
            note=args.note,
            at=_now(),
        )
    except TransactionStateError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    print(f"{args.key}: {previous} -> {_AS[args.resolution]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
