"""
Mutual checkpoints: each party holds the other's history commitment.

When two organisations' agents transact, each side's audit log is its own
word. A signed checkpoint (``agent_dna.checkpoint``) commits a log to a
count and a running hash, but a checkpoint its own operator keeps can be
replaced along with the records.

So the parties exchange them. A ``CounterpartyLedger`` is one side's
append-only store of the OTHER side's checkpoints:

    accept(checkpoint)   keep it, after checking it is signed by the
                         counterparty's pinned key, its hash is intact and
                         it does not go backwards from the last one held
    acknowledge(...)     a signed receipt that says "I hold checkpoint X",
                         which the counterparty keeps as proof it disclosed
    audit(export)        does a later export from the counterparty still
                         contain everything every held checkpoint covers?

After that, a party that drops or rewrites records produces an export that
fails ``audit`` against a checkpoint the other party holds, and it cannot
alter that copy.

Limits:
    * Only records that existed when a checkpoint was exchanged are
      covered. The exchange interval is the exposure.
    * Two checkpoints can be compared by count without the records, not by
      content: ``accept`` refuses a count that goes down or a different head
      at the same count, and ``audit`` does the full check.
    * The ledger file is this party's own. Protecting it from this party's
      own operator is out of scope.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ..checkpoint import SPEC as CHECKPOINT_SPEC
from ..checkpoint import checkpoint_hash, export_failures, signature_problem

ACK_SPEC = "pv-checkpoint-ack/1"
_ACK_TAG = b"pv-checkpoint-ack/1:"


class CheckpointRejected(ValueError):  # noqa: N818 - reads as the event
    """The counterparty's checkpoint was not kept. The message says why."""


def _ack_hash(ack: dict[str, Any]) -> str:
    body = {k: v for k, v in ack.items() if k not in ("ack_hash", "signature")}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(_ACK_TAG + canonical.encode()).hexdigest()


class CounterpartyLedger:
    def __init__(self, path: str | Path, trusted_keys: Iterable[str]) -> None:
        self.path = Path(path)
        self.trusted_keys = frozenset(trusted_keys)
        if not self.trusted_keys:
            raise ValueError("at least one counterparty public key must be pinned")
        self._lock = threading.Lock()

    def held(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with open(self.path, encoding="utf-8") as handle:
            return [json.loads(line) for line in handle if line.strip()]

    def accept(self, checkpoint: Any) -> dict[str, Any]:
        """Verify and keep one counterparty checkpoint."""
        if not isinstance(checkpoint, dict):
            raise CheckpointRejected("not an object")
        if checkpoint.get("spec") != CHECKPOINT_SPEC:
            raise CheckpointRejected(f"spec is not {CHECKPOINT_SPEC}")
        count = checkpoint.get("record_count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise CheckpointRejected("record_count is not a count")
        if checkpoint.get("checkpoint_hash") != checkpoint_hash(checkpoint):
            raise CheckpointRejected("checkpoint_hash mismatch: contents were altered")
        problem = signature_problem(checkpoint, self.trusted_keys)
        if problem is not None:
            raise CheckpointRejected(problem)

        with self._lock:
            held = self.held()
            if any(c["checkpoint_hash"] == checkpoint["checkpoint_hash"] for c in held):
                return checkpoint  # already held: accepting twice is harmless
            if held:
                last = max(held, key=lambda c: c["record_count"])
                if count < last["record_count"]:
                    raise CheckpointRejected(
                        f"goes backwards: covers {count} records, a held "
                        f"checkpoint covers {last['record_count']}"
                    )
                if (
                    count == last["record_count"]
                    and checkpoint["log_head"] != last["log_head"]
                ):
                    raise CheckpointRejected(
                        "same record count as a held checkpoint, different "
                        "log head: the counterparty's history was rewritten"
                    )
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(checkpoint, sort_keys=True) + "\n")
        return checkpoint

    def acknowledge(self, checkpoint: dict[str, Any], signer: Any) -> dict[str, Any]:
        """Signed receipt for a checkpoint this ledger holds."""
        digest = checkpoint["checkpoint_hash"]
        if not any(c["checkpoint_hash"] == digest for c in self.held()):
            raise CheckpointRejected("cannot acknowledge a checkpoint not held")
        ack: dict[str, Any] = {
            "spec": ACK_SPEC,
            "checkpoint_hash": digest,
            "record_count": checkpoint["record_count"],
            "acknowledged_at": time.time(),
        }
        ack["ack_hash"] = _ack_hash(ack)
        ack["signature"] = signer.sign_hash(ack["ack_hash"]).to_dict()
        return ack

    def audit(self, lines: Iterable[str]) -> list[str]:
        """Check a counterparty export against every checkpoint held.

        Returns the failures; an empty list means the export still contains
        everything each held checkpoint committed to.
        """
        held = self.held()
        if not held:
            return ["no counterparty checkpoint is held: nothing to audit against"]
        records = [json.loads(line) for line in lines if line.strip()]
        failures: list[str] = []
        for checkpoint in held:
            failures.extend(export_failures(checkpoint, records))
        return failures


def verify_acknowledgement(
    ack: Any, checkpoint: dict[str, Any], holder_keys: Iterable[str]
) -> str | None:
    """None when ``ack`` proves a pinned holder took ``checkpoint``."""
    if not isinstance(ack, dict) or ack.get("spec") != ACK_SPEC:
        return f"not a {ACK_SPEC} acknowledgement"
    if ack.get("checkpoint_hash") != checkpoint.get("checkpoint_hash"):
        return "acknowledges a different checkpoint"
    if ack.get("ack_hash") != _ack_hash(ack):
        return "ack_hash mismatch: contents were altered"
    envelope = ack.get("signature")
    if not isinstance(envelope, dict) or envelope.get("signed_hash") != ack["ack_hash"]:
        return "signature covers a different hash"
    return signature_problem(
        {"checkpoint_hash": ack["ack_hash"], "signature": envelope},
        frozenset(holder_keys),
    )
