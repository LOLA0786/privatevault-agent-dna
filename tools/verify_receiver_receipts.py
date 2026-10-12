#!/usr/bin/env python3
"""Independent verifier for PrivateVault receiver receipts (ADR 0019).

Does not import ``agent_dna``. Chain mode uses the standard library only;
signature mode additionally needs PyNaCl and the receiver operator's
published public key(s), supplied on the command line, never read from the
receipts.

Receipts restrict values to ASCII-keyed strings, safe integers, and null, so
RFC 8785 canonical JSON for them equals ``json.dumps(sort_keys=True,
separators=(",", ":"), ensure_ascii=False)``. The parity test pins this.

Usage:
  verify_receiver_receipts.py --db receiver.db --receiver-id core-banking.bank.example \
      [--receiver-key bank-receiver-01=BASE64PUBKEY ...]
  verify_receiver_receipts.py --jsonl receipts.jsonl --receiver-id ...

Exit 0 when every check passes, 1 otherwise.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sqlite3
import sys
from collections.abc import Iterable

SPEC = "pv-receiver-receipt/0.1-experimental"
GENESIS = "sha256:" + "0" * 64
FIELDS = {
    "spec",
    "canonicalization",
    "receiver_id",
    "sequence",
    "previous_receipt_digest",
    "received_at",
    "outcome",
    "reason_code",
    "method",
    "path",
    "wire_bytes_digest",
    "wire_bytes_length",
    "execution_authorization_id",
    "execution_authorization_digest",
    "organisation_id",
    "action_digest",
    "receipt_key_id",
    "signature",
}


def canonical(value: dict) -> bytes:
    for key, item in value.items():
        if not key.isascii():
            raise ValueError("non-ASCII key")
        if isinstance(item, bool) or not (item is None or isinstance(item, (str, int))):
            raise ValueError(f"unsupported value for {key}")
        if isinstance(item, int) and not 0 <= item <= (1 << 53) - 1:
            raise ValueError(f"integer out of range for {key}")
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def digest(value: dict) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def _load(args: argparse.Namespace) -> list[dict]:
    if args.db:
        conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
        try:
            rows = conn.execute(
                "SELECT receipt_json FROM receiver_receipts ORDER BY sequence"
            ).fetchall()
        finally:
            conn.close()
        return [json.loads(r[0]) for r in rows]
    with open(args.jsonl, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def verify(  # noqa: C901 - ordered checklist mirrors the gate
    receipts: Iterable[dict], *, receiver_id: str, keys: dict[str, str] | None
) -> list[str]:
    verify_key = None
    if keys is not None:
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey

        def verify_key(receipt: dict) -> str | None:
            public = keys.get(receipt["receipt_key_id"])
            if public is None:
                return "receipt_key_id is not a published receiver key"
            sig = receipt["signature"]
            if not isinstance(sig, str) or not sig.startswith("ed25519:"):
                return "malformed signature"
            unsigned = {k: v for k, v in receipt.items() if k != "signature"}
            try:
                VerifyKey(base64.b64decode(public, validate=True)).verify(
                    canonical(unsigned),
                    base64.b64decode(sig.removeprefix("ed25519:"), validate=True),
                )
            except (BadSignatureError, ValueError):
                return "signature invalid"
            return None

    failures: list[str] = []
    previous = GENESIS
    expected = 1
    for index, receipt in enumerate(receipts):
        where = f"receipt[{index}]"
        if set(receipt) != FIELDS or receipt.get("spec") != SPEC:
            failures.append(f"{where}: shape or spec invalid")
            break
        if receipt["receiver_id"] != receiver_id:
            failures.append(f"{where}: receiver_id differs")
        if receipt["sequence"] != expected:
            failures.append(f"{where}: sequence {receipt['sequence']} != {expected}")
        if receipt["previous_receipt_digest"] != previous:
            failures.append(f"{where}: previous_receipt_digest does not link")
        if (receipt["outcome"] == "ADMITTED") != (receipt["reason_code"] is None):
            failures.append(f"{where}: outcome/reason_code inconsistent")
        if verify_key is not None:
            problem = verify_key(receipt)
            if problem:
                failures.append(f"{where}: {problem}")
        try:
            previous = digest(receipt)
        except ValueError as exc:
            failures.append(f"{where}: {exc}")
            break
        expected = int(receipt["sequence"]) + 1
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--db")
    source.add_argument("--jsonl")
    parser.add_argument("--receiver-id", required=True)
    parser.add_argument(
        "--receiver-key",
        action="append",
        default=[],
        help="KEY_ID=BASE64_ED25519_PUBLIC_KEY (repeatable). Omit for chain-only.",
    )
    args = parser.parse_args(argv)
    keys = None
    if args.receiver_key:
        keys = {}
        for item in args.receiver_key:
            key_id, _, public = item.partition("=")
            if not key_id or not public:
                parser.error("--receiver-key must be KEY_ID=BASE64")
            keys[key_id] = public
    receipts = _load(args)
    failures = verify(receipts, receiver_id=args.receiver_id, keys=keys)
    mode = "chain+signatures" if keys else "chain-only (signatures NOT checked)"
    if failures:
        print(f"FAIL {len(receipts)} receipts, mode={mode}")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    admitted = sum(1 for r in receipts if r["outcome"] == "ADMITTED")
    print(
        f"OK {len(receipts)} receipts ({admitted} admitted, "
        f"{len(receipts) - admitted} refused), mode={mode}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
