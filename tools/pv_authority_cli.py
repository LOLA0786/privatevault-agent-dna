#!/usr/bin/env python3
"""Authority Provenance v0.1-experimental command-line tooling.

This command can run offline without the PrivateVault API, database, or hosted
service. It imports and delegates verification to agent_dna.authority_v01, so
it is runtime-coupled and is not an independently implemented verifier.

Exit codes:
  0  verified and conformant, or scan completed
  1  invalid, unverifiable, or non-conformant evidence
  2  usage, input, or configuration error
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Permit direct execution from a source checkout.
sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1]),
)

from agent_dna.authority_v01 import (  # noqa: E402
    AuthorityFormatError,
    VerificationReport,
    scan_authority_records,
    strict_json_loads,
    verify_receipt,
    verify_receipt_sequence,
)

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2


def _read_json(path: str) -> Any:
    try:
        return strict_json_loads(Path(path).read_bytes())
    except OSError as exc:
        raise AuthorityFormatError(f"cannot read {path}: {exc}") from exc


def _read_jsonl(path: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise AuthorityFormatError(f"cannot read {path}: {exc}") from exc

    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue

        value = strict_json_loads(line)

        if not isinstance(value, dict):
            raise AuthorityFormatError(
                f"{path} line {line_number}: expected a JSON object"
            )

        records.append(value)

    return records


def _print_verification(
    report: VerificationReport,
    *,
    index: int | None = None,
) -> None:
    prefix = f"receipt {index}: " if index is not None else ""

    print(f"{prefix}evidence_state       {report.evidence_state.value}")

    print(f"{prefix}decision_conformance {report.decision_conformance.value}")

    if report.accountable_principal:
        print(f"{prefix}accountable_principal {report.accountable_principal}")

    if report.reason_code:
        print(f"{prefix}reason_code          {report.reason_code}")

    for failure in report.failures:
        print(f"{prefix}failure              {failure}")


def cmd_verify(args: argparse.Namespace) -> int:
    receipt = _read_json(args.receipt)
    bundle = _read_json(args.trust_bundle)

    if not isinstance(receipt, dict) or not isinstance(bundle, dict):
        raise AuthorityFormatError("receipt and trust bundle must be JSON objects")

    report = verify_receipt(
        receipt,
        bundle,
    )

    _print_verification(report)

    if args.json:
        Path(args.json).write_text(
            json.dumps(
                report.to_dict(),
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    return EXIT_OK if report.ok else EXIT_FAIL


def cmd_verify_sequence(args: argparse.Namespace) -> int:
    receipts = _read_jsonl(args.receipts)
    bundle = _read_json(args.trust_bundle)

    if not isinstance(bundle, dict):
        raise AuthorityFormatError("trust bundle must be a JSON object")

    reports = verify_receipt_sequence(
        receipts,
        bundle,
    )

    for index, report in enumerate(reports, 1):
        _print_verification(
            report,
            index=index,
        )

    if args.json:
        Path(args.json).write_text(
            json.dumps(
                [report.to_dict() for report in reports],
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

    return EXIT_OK if reports and all(report.ok for report in reports) else EXIT_FAIL


def _print_scan(report: dict[str, Any]) -> None:
    evidence = report["evidence_state"]

    print("\npv authority scan - AUTHORISATION READINESS ASSESSMENT")
    print("=" * 64)

    print(f"Actions analysed   {report['actions_analysed']}")

    print(
        "Evidence           "
        f"VERIFIED {evidence['VERIFIED']}   "
        f"INVALID {evidence['INVALID']}   "
        f"UNVERIFIABLE {evidence['UNVERIFIABLE']}   "
        f"ABSENT {evidence['ABSENT']}"
    )

    if evidence["ABSENT"]:
        print("\nFINDING")
        print("Your agent infrastructure does not currently emit authority evidence.")
        print(
            "This is the industry norm. Consequently these "
            "actions cannot be shown to derive from an "
            "accountable signed grant chain, nor shown not to."
        )

        print("\nTO REACH VERIFIED, EMIT")
        print("  signed grant chain (root first)")
        print("  trust bundle pinned out of band")
        print("  decision_timestamp and request_id")
        print("  subject key id and decision_input_digest")

    if report["critical_findings"]:
        print("\nCRITICAL FINDINGS")

        for finding in report["critical_findings"]:
            print(f"  row {finding['row']}: VERIFIED evidence, NON_CONFORMANT ALLOW")

            if finding["accountable_principal"]:
                print(f"    accountable principal: {finding['accountable_principal']}")


def cmd_scan(args: argparse.Namespace) -> int:
    records = _read_jsonl(args.input)

    bundle = _read_json(args.trust_bundle) if args.trust_bundle else None

    if bundle is not None and not isinstance(bundle, dict):
        raise AuthorityFormatError("trust bundle must be a JSON object")

    report = scan_authority_records(
        records,
        bundle,
    )

    _print_scan(report)

    if args.json:
        Path(args.json).write_text(
            json.dumps(report, indent=2) + "\n",
            encoding="utf-8",
        )

    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=("Authority Provenance v0.1-experimental offline tooling")
    )

    sub = parser.add_subparsers(
        dest="command",
        required=True,
    )

    verify = sub.add_parser(
        "verify",
        help="verify one receipt",
    )
    verify.add_argument("receipt")
    verify.add_argument("trust_bundle")
    verify.add_argument(
        "--json",
        help="write machine-readable result",
    )
    verify.set_defaults(func=cmd_verify)

    sequence = sub.add_parser(
        "verify-sequence",
        help="verify receipt linkage in a JSONL sequence",
    )
    sequence.add_argument("receipts")
    sequence.add_argument("trust_bundle")
    sequence.add_argument(
        "--json",
        help="write machine-readable results",
    )
    sequence.set_defaults(func=cmd_verify_sequence)

    scan = sub.add_parser(
        "scan",
        help="assess authority-evidence readiness",
    )
    scan.add_argument(
        "input",
        help="JSONL actions, receipts, or wrapper records",
    )
    scan.add_argument(
        "--trust-bundle",
        help=("out-of-band trust bundle; absence produces UNVERIFIABLE evidence"),
    )
    scan.add_argument(
        "--json",
        help="write machine-readable report",
    )
    scan.set_defaults(func=cmd_scan)

    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        return int(args.func(args))

    except AuthorityFormatError as exc:
        print(
            f"error: {exc}",
            file=sys.stderr,
        )
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
