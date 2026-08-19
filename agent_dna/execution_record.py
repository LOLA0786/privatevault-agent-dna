"""
ExecutionEvent — append-only executor feedback for a decision.

Sealed DecisionRecords are immutable (outcome="pending" is inside the
hash), so execution results are reported as NEW records, never as
mutations.

Anchor chaining
---------------
An ExecutionEvent's prev_hash is the record_hash of the DecisionRecord
it reports on. This cryptographically binds result to decision: alter
the decision and its execution event no longer verifies against it.

Divergence
----------
status="ok" on an event whose decision was "block" is an enforcement
divergence — the runtime said no and the world said yes. That is the
exact failure class from the earlier executed:True incident, now
detectable from the audit file alone.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

VALID_STATUS = ("ok", "error", "refused", "indeterminate")


def require_honest_outcome_status(*, dispatched: bool, status: str) -> None:
    """Refuse to treat a non-dispatch as successful execution.

    `ok` means the tool ran. An execution that was not dispatched must
    never be recorded as `ok`. Callers that omit `dispatched` keep the
    legacy executor-attestation path.
    """
    if status == "ok" and not dispatched:
        raise ValueError("undispatched execution cannot be recorded as ok")


PROTOCOL_VERSION = "drp/0.1"


@dataclass
class ExecutionEvent:
    kind: str = field(default="execution", init=False)
    protocol_version: str = field(default=PROTOCOL_VERSION, init=False)
    event_id: str = ""
    agent_id: str = ""
    decision_ref: str = ""  # decision_id this reports on
    status: str = ""  # "ok" | "error" | "refused" | "indeterminate"
    detail: str = ""
    edges: list[dict[str, str]] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    prev_hash: str = ""  # record_hash of the decision (anchor)
    record_hash: str = ""
    # Optional exact-byte witness of the upstream response. Omitted from
    # the hashed payload when empty so existing sealed events still verify.
    response_digest: str = ""

    def payload(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "kind": self.kind,
            "protocol_version": self.protocol_version,
            "event_id": self.event_id,
            "agent_id": self.agent_id,
            "decision_ref": self.decision_ref,
            "status": self.status,
            "detail": self.detail,
            "edges": self.edges,
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash,
        }
        if self.response_digest:
            d["response_digest"] = self.response_digest
        return d

    def compute_hash(self) -> str:
        canonical = json.dumps(
            self.payload(), sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    def seal(self) -> ExecutionEvent:
        self.record_hash = self.compute_hash()
        return self

    def verify(self) -> bool:
        return self.record_hash != "" and self.record_hash == self.compute_hash()

    def to_dict(self) -> dict[str, Any]:
        d = self.payload()
        d["record_hash"] = self.record_hash
        return d


def build_execution_event(
    *,
    agent_id: str,
    decision_id: str,
    decision_hash: str,
    status: str,
    detail: str = "",
    response_digest: str = "",
) -> ExecutionEvent:
    if status not in VALID_STATUS:
        raise ValueError(f"status must be one of {VALID_STATUS}, got {status!r}")
    if response_digest:
        if not (
            response_digest.startswith("sha256:")
            and len(response_digest) == 71
            and all(c in "0123456789abcdef" for c in response_digest[7:])
        ):
            raise ValueError("response_digest must be sha256:<64 lowercase hex>")
    ev = ExecutionEvent(
        event_id=str(uuid.uuid4()),
        agent_id=agent_id,
        decision_ref=decision_id,
        status=status,
        detail=detail,
        edges=[{"type": "resulted_in", "target": decision_id}],
        prev_hash=decision_hash,
        response_digest=response_digest,
    )
    return ev.seal()
