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

VALID_STATUS = ("ok", "error", "refused")


PROTOCOL_VERSION = "drp/0.2"

# Mirrors decision_record.COMMITMENT_ALGORITHMS. Duplicated rather
# than imported: execution_record must not depend on decision_record.
COMMITMENT_ALGORITHMS = ("sha-256", "sha3-256")


@dataclass
class ExecutionEvent:
    kind: str = field(default="execution", init=False)
    protocol_version: str = field(default=PROTOCOL_VERSION, init=False)
    event_id: str = ""
    agent_id: str = ""
    decision_ref: str = ""              # decision_id this reports on
    status: str = ""                    # "ok" | "error" | "refused"
    detail: str = ""
    edges: list[dict[str, str]] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    prev_hash: str = ""                 # record_hash of the decision (anchor)
    record_hash: str = ""
    commitments: dict[str, str] = field(default_factory=dict)

    def payload(self) -> dict[str, Any]:
        return {
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

    def canonical_bytes(self) -> bytes:
        """The exact octets every commitment is computed over."""
        return json.dumps(
            self.payload(),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()

    def compute_commitments(self) -> dict[str, str]:
        raw = self.canonical_bytes()
        return {
            "sha-256": hashlib.sha256(raw).hexdigest(),
            "sha3-256": hashlib.sha3_256(raw).hexdigest(),
        }

    def compute_hash(self) -> str:
        canonical = json.dumps(
            self.payload(), sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    def seal(self) -> ExecutionEvent:
        self.commitments = self.compute_commitments()
        self.record_hash = self.commitments["sha-256"]
        return self

    def verify(self) -> bool:
        if self.record_hash == "" or not self.commitments:
            return False
        expected = self.compute_commitments()
        for algorithm in COMMITMENT_ALGORITHMS:
            if algorithm not in self.commitments:
                return False
        # Every entry present is recomputed: an unchecked entry is an
        # unchecked claim, including one this verifier does not prefer.
        for algorithm, digest in self.commitments.items():
            if algorithm not in expected or expected[algorithm] != digest:
                return False
        return self.record_hash == self.commitments["sha-256"]

    def to_dict(self) -> dict[str, Any]:
        d = self.payload()
        d["record_hash"] = self.record_hash
        d["commitments"] = dict(self.commitments)
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
