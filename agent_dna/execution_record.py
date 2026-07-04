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
from typing import Any, Dict, List

VALID_STATUS = ("ok", "error", "refused")


@dataclass
class ExecutionEvent:
    kind: str = field(default="execution", init=False)
    event_id: str = ""
    agent_id: str = ""
    decision_ref: str = ""              # decision_id this reports on
    status: str = ""                    # "ok" | "error" | "refused"
    detail: str = ""
    edges: List[Dict[str, str]] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    prev_hash: str = ""                 # record_hash of the decision (anchor)
    record_hash: str = ""

    def payload(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "event_id": self.event_id,
            "agent_id": self.agent_id,
            "decision_ref": self.decision_ref,
            "status": self.status,
            "detail": self.detail,
            "edges": self.edges,
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash,
        }

    def compute_hash(self) -> str:
        canonical = json.dumps(
            self.payload(), sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    def seal(self) -> "ExecutionEvent":
        self.record_hash = self.compute_hash()
        return self

    def verify(self) -> bool:
        return (
            self.record_hash != ""
            and self.record_hash == self.compute_hash()
        )

    def to_dict(self) -> Dict[str, Any]:
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
) -> ExecutionEvent:
    if status not in VALID_STATUS:
        raise ValueError(f"status must be one of {VALID_STATUS}, got {status!r}")
    ev = ExecutionEvent(
        event_id=str(uuid.uuid4()),
        agent_id=agent_id,
        decision_ref=decision_id,
        status=status,
        detail=detail,
        edges=[{"type": "resulted_in", "target": decision_id}],
        prev_hash=decision_hash,
    )
    return ev.seal()
