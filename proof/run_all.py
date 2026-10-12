"""One command: run P1, P2, and P3 and print the results.

    uv run python -m proof.run_all
    docker compose -f proof/docker-compose.yml up

Exit status 0 only if every proof holds.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from proof.before_after import run as before_after
from proof.compare import run as compare
from proof.injection import run as injection


def _banner(title: str) -> None:
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--run-dir", default=None)
    args = parser.parse_args(argv)
    run_dir = (
        Path(args.run_dir)
        if args.run_dir
        else Path(tempfile.mkdtemp(prefix="pv-proof-"))
    )
    run_dir.mkdir(parents=True, exist_ok=True)

    _banner("P1 comparison: one attack, four controls")
    ok1 = compare.main(["--results", str(run_dir / "RESULTS.md")]) == 0

    _banner("P2 before/after: finance ops with PrivateVault off, then on")
    ok2 = before_after.main(["--run-dir", str(run_dir / "p2")]) == 0

    _banner("P3 injection: an invoice note rewrites the payee")
    ok3 = injection.main(["--run-dir", str(run_dir / "p3")]) == 0

    _banner("summary")
    for label, ok in (
        ("P1 comparison", ok1),
        ("P2 before/after", ok2),
        ("P3 injection", ok3),
    ):
        print(f"  {label:<18} {'holds' if ok else 'FAILED'}")
    print()
    if ok1 and ok2 and ok3:
        print("ALL PROOFS HOLD")
        return 0
    print("SOME PROOFS FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
