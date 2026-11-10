"""
Signed log checkpoints -- completeness for the audit trail.

The per-agent hash chain proves that the records in an export were not
edited and that no record was removed from the MIDDLE of an agent's chain.
It cannot show that records are missing from the END of a chain, that a
whole agent is missing, or that an execution event was removed: an
execution hangs off its decision alone, so deleting it leaves nothing
dangling. Signatures do not help, because a deleted record's envelope is
deleted with it. The independent verifier passed all three.

A checkpoint closes that. It commits to the whole log in append order:

    log_head_0 = sha256("pv-log/1")
    log_head_i = sha256(log_head_{i-1} || record_hash_i)

together with the record count, the decision and execution counts, and each
agent's chain head. It is signed with the receipt key. ``verify_records.py
--checkpoint`` then requires an export to EXTEND the checkpoint: the first
``record_count`` records must reproduce ``log_head`` exactly. Any deletion,
reordering or substitution among those records changes the head.

What it takes to be useful: the checkpoint must be held by someone other
than the party who could delete records -- the customer, an auditor, a
write-once bucket. A checkpoint fetched from the operator together with the
export only proves the two agree. Fetch checkpoints on a schedule, keep
them, and verify every later export against every one you hold.

The signature covers ``sha256("pv-checkpoint/1:" || canonical JSON)``, so a
checkpoint signature can never be presented as a record signature: record
hashes are taken over bare canonical JSON, which never starts with that tag.

    python -m agent_dna.checkpoint records.jsonl --out checkpoint.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
import time
import uuid
from collections.abc import Iterable
from pathlib import Path
from typing import Any

SPEC = "pv-checkpoint/1"
LOG_GENESIS = hashlib.sha256(b"pv-log/1").hexdigest()
_SIGNING_TAG = b"pv-checkpoint/1:"


def advance(head: str, record_hash: str) -> str:
    """One step of the log accumulator."""
    return hashlib.sha256((head + record_hash).encode()).hexdigest()


def checkpoint_hash(checkpoint: dict[str, Any]) -> str:
    """Hash the signature covers: every field except hash and signature."""
    body = {
        k: v for k, v in checkpoint.items() if k not in ("checkpoint_hash", "signature")
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(_SIGNING_TAG + canonical.encode()).hexdigest()


def build_checkpoint(
    lines: Iterable[str],
    *,
    signer: Any = None,
    now: float | None = None,
) -> dict[str, Any]:
    """Checkpoint over an export's records, in file order.

    ``signer`` is a ReceiptSigner (anything with ``sign_hash``); without one
    the checkpoint is unsigned and a verifier given trusted keys rejects it.
    """
    head = LOG_GENESIS
    total = decisions = executions = 0
    agents: dict[str, dict[str, Any]] = {}
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        record = json.loads(line)
        record_hash = record["record_hash"]
        head = advance(head, record_hash)
        total += 1
        if record.get("kind", "decision") == "execution":
            executions += 1
        else:
            decisions += 1
            entry = agents.setdefault(
                str(record.get("agent_id")), {"decisions": 0, "head": ""}
            )
            entry["decisions"] += 1
            entry["head"] = record_hash

    checkpoint: dict[str, Any] = {
        "spec": SPEC,
        "checkpoint_id": f"cp-{uuid.uuid4()}",
        "created_at": time.time() if now is None else float(now),
        "record_count": total,
        "decision_count": decisions,
        "execution_count": executions,
        "log_head": head,
        "agents": agents,
    }
    digest = checkpoint_hash(checkpoint)
    checkpoint["checkpoint_hash"] = digest
    checkpoint["signature"] = (
        signer.sign_hash(digest).to_dict() if signer is not None else None
    )
    return checkpoint


def checkpoint_for_store(store: Any, *, signer: Any = None) -> dict[str, Any]:
    """Checkpoint of everything a store would export right now."""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(store.export_jsonl(Path(tmp) / "records.jsonl"))
        with open(path, encoding="utf-8") as handle:
            return build_checkpoint(handle, signer=signer)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Produce a signed checkpoint for a DRP record export."
    )
    parser.add_argument("records", help="record JSONL export")
    parser.add_argument("--out", help="write the checkpoint here (default: stdout)")
    args = parser.parse_args(argv)

    from .signer import KEY_ENV, ReceiptSigner

    signer = ReceiptSigner() if os.getenv(KEY_ENV) else None
    with open(args.records, encoding="utf-8") as handle:
        checkpoint = build_checkpoint(handle, signer=signer)
    text = json.dumps(checkpoint, sort_keys=True, indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    if signer is None:
        print(
            f"warning: {KEY_ENV} is not set; the checkpoint is UNSIGNED",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
