"""Export the receiver ledger's receipt chain to JSON Lines.

    python -m network.receiver_kit.export_receipts --db data/receiver.db --out receipts.jsonl

Standard library only, read-only connection. The output is what a partner
hands back for verification, together with their receiver public key. The
ledger file itself and the private key stay with the partner.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path


def export(db: Path, out: Path) -> int:
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        rows = conn.execute(
            "SELECT receipt_json FROM receiver_receipts ORDER BY sequence ASC"
        ).fetchall()
    finally:
        conn.close()
    with out.open("w", encoding="utf-8") as fh:
        for (raw,) in rows:
            fh.write(json.dumps(json.loads(raw), sort_keys=True) + "\n")
    return len(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    db = Path(args.db)
    if not db.exists():
        print(f"no ledger at {db}", file=sys.stderr)
        return 1
    count = export(db, Path(args.out))
    print(f"wrote {count} receipts to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
