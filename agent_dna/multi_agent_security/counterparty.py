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
import math
import threading
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ..checkpoint import SPEC as CHECKPOINT_SPEC
from ..checkpoint import checkpoint_hash, export_failures, signature_problem

ACK_SPEC = "pv-checkpoint-ack/1"
_ACK_TAG = b"pv-checkpoint-ack/1:"
_ACK_FIELDS = frozenset(
    {
        "spec",
        "checkpoint_hash",
        "record_count",
        "acknowledged_at",
        "ack_hash",
        "signature",
    }
)


class CheckpointRejected(ValueError):  # noqa: N818 - reads as the event
    """The counterparty's checkpoint was not kept. The message says why."""


def _ack_hash(ack: dict[str, Any]) -> str:
    body = {k: v for k, v in ack.items() if k not in ("ack_hash", "signature")}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(_ACK_TAG + canonical.encode()).hexdigest()


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key!r}")
        result[key] = value
    return result


def _load(line: str) -> Any:
    value = json.loads(line, object_pairs_hook=_object)
    # Also refuses NaN, Infinity and exponent overflow (e.g. 1e400), even
    # inside nested fields. These must never acquire two interpretations.
    json.dumps(value, allow_nan=False)
    return value


def _count(value: Any) -> bool:
    return type(value) is int and value >= 0


def _hex(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def _finite(value: Any) -> bool:
    try:
        return type(value) in (int, float) and math.isfinite(value)
    except OverflowError:
        return False


def _checkpoint_problem(checkpoint: Any) -> str | None:
    if not isinstance(checkpoint, dict):
        return "not an object"
    if checkpoint.get("spec") != CHECKPOINT_SPEC:
        return f"spec is not {CHECKPOINT_SPEC}"
    if not _count(checkpoint.get("record_count")):
        return "record_count is not a count"
    if not _hex(checkpoint.get("log_head")):
        return "log_head is not a hash"
    try:
        json.dumps(checkpoint, allow_nan=False)
        if checkpoint.get("checkpoint_hash") != checkpoint_hash(checkpoint):
            return "checkpoint_hash mismatch: contents were altered"
    except (TypeError, ValueError, RecursionError):
        return "checkpoint is not finite JSON"
    return None


def _record_hash(record: dict[str, Any]) -> str:
    # The DRP raw-record check used by tools/verify_records.py::compute_hash.
    # Keep that standalone verifier independent; parity is regression-tested.
    body = {k: v for k, v in record.items() if k != "record_hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _export_records(lines: Iterable[str]) -> tuple[list[dict[str, Any]], list[str]]:
    records: list[dict[str, Any]] = []
    failures: list[str] = []
    try:
        for number, line in enumerate(lines, 1):
            try:
                if not isinstance(line, str):
                    raise ValueError("expected a JSONL string")
                if not line.strip():
                    continue
                record = _load(line)
                if not isinstance(record, dict):
                    raise ValueError("expected a JSON object")
                records.append(record)
                if record.get("record_hash") != _record_hash(record):
                    failures.append(f"line {number}: record_hash mismatch")
            except (TypeError, ValueError, RecursionError) as exc:
                failures.append(f"line {number}: invalid record ({exc})")
    except (OSError, UnicodeError) as exc:
        failures.append(f"cannot read export: {exc}")
    return records, failures


class CounterpartyLedger:
    def __init__(self, path: str | Path, trusted_keys: Iterable[str]) -> None:
        self.path = Path(path)
        self.trusted_keys = frozenset(trusted_keys)
        if not self.trusted_keys:
            raise ValueError("at least one counterparty public key must be pinned")
        self._lock = threading.Lock()

    def held(self) -> list[dict[str, Any]]:
        try:
            with open(self.path, encoding="utf-8") as handle:
                held = [_load(line) for line in handle if line.strip()]
            for checkpoint in held:
                self._validate(checkpoint)
            return held
        except FileNotFoundError:
            return []
        except (OSError, ValueError, RecursionError) as exc:
            raise CheckpointRejected(f"cannot read held checkpoints: {exc}") from exc

    def _validate(self, checkpoint: Any) -> None:
        problem = _checkpoint_problem(checkpoint)
        if problem is None:
            problem = signature_problem(checkpoint, self.trusted_keys)
        if problem is not None:
            raise CheckpointRejected(problem)

    def accept(self, checkpoint: Any) -> dict[str, Any]:
        """Verify and keep one counterparty checkpoint."""
        self._validate(checkpoint)
        checkpoint = _load(json.dumps(checkpoint))  # own the validated snapshot
        self._validate(checkpoint)
        count = checkpoint["record_count"]

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
        """Signed receipt made from the validated, stored checkpoint."""
        self._validate(checkpoint)
        digest = checkpoint["checkpoint_hash"]
        with self._lock:
            stored = next(
                (c for c in self.held() if c["checkpoint_hash"] == digest), None
            )
        if stored is None:
            raise CheckpointRejected("cannot acknowledge a checkpoint not held")
        ack: dict[str, Any] = {
            "spec": ACK_SPEC,
            "checkpoint_hash": stored["checkpoint_hash"],
            "record_count": stored["record_count"],
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
        try:
            held = self.held()
        except CheckpointRejected as exc:
            return [str(exc)]
        if not held:
            return ["no counterparty checkpoint is held: nothing to audit against"]
        records, failures = _export_records(lines)
        for checkpoint in held:
            failures.extend(export_failures(checkpoint, records))
        return failures


def verify_acknowledgement(
    ack: Any, checkpoint: dict[str, Any], holder_keys: Iterable[str]
) -> str | None:
    """None when a pinned holder acknowledges this checkpoint's contents.

    This authenticates the holder. Authenticate the checkpoint issuer
    separately (e.g. with ``CounterpartyLedger.accept``) when required.
    """
    if not isinstance(ack, dict) or ack.get("spec") != ACK_SPEC:
        return f"not a {ACK_SPEC} acknowledgement"
    problem = _checkpoint_problem(checkpoint)
    if problem is not None:
        return f"invalid checkpoint: {problem}"
    if ack.get("checkpoint_hash") != checkpoint.get("checkpoint_hash"):
        return "acknowledges a different checkpoint"
    if set(ack) != _ACK_FIELDS:
        return "unexpected or missing acknowledgement fields"
    try:
        if ack.get("ack_hash") != _ack_hash(ack):
            return "ack_hash mismatch: contents were altered"
    except (TypeError, ValueError, RecursionError):
        return "acknowledgement is not finite JSON"
    if (
        not _count(ack["record_count"])
        or ack["record_count"] != checkpoint["record_count"]
    ):
        return "acknowledgement record_count does not match checkpoint"
    if not _finite(ack["acknowledged_at"]):
        return "acknowledgement timestamp is not finite"
    envelope = ack.get("signature")
    if not isinstance(envelope, dict) or envelope.get("signed_hash") != ack["ack_hash"]:
        return "signature covers a different hash"
    return signature_problem(
        {"checkpoint_hash": ack["ack_hash"], "signature": envelope},
        frozenset(holder_keys),
    )
