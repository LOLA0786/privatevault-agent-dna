"""
DecisionRecord — the canonical, persistable runtime decision object.

One record per processed AgentAction. Sits OUTSIDE the DecisionEngine:
the engine decides, the recorder records. Nothing in the enforcement
path depends on this module.

Field honesty
-------------
goal / intent / policy_id / approval_ref are Optional because nothing
in this runtime produces them yet. They are schema-reserved, not
populated. Do not claim them until a component writes them.

Tamper evidence
---------------
Records are hash-chained: record_hash = sha256(canonical_payload +
prev_hash). This makes the record stream receipt-compatible from day
one and lets an independent verifier detect deletion or reordering.
Signing (Ed25519) is deliberately NOT here — that belongs to the
PrivateVault receipt layer; this repo emits chainable records, the
vault signs them.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .decision import DecisionResult
from .trace import AgentAction

GENESIS_HASH = "0" * 64


PROTOCOL_VERSION = "drp/0.1"


@dataclass
class DecisionRecord:
    # identity / lineage
    kind: str = field(default="decision", init=False)   # record discriminator
    protocol_version: str = field(default=PROTOCOL_VERSION, init=False)
    decision_id: str
    parent_decision: Optional[str]      # previous record for this agent (chain, not DAG — yet)
    agent_id: str
    capability: str

    # the decision itself
    decision: str                       # "allow" | "require_approval" | "block"
    triggered_by: str
    reason: str
    severity: str
    drift_score: float
    evidence: List[Dict[str, Any]]
    evidence_strength: float

    # execution context
    arguments_digest: str               # sha256 of canonical arguments — never raw payloads
    outcome: str                        # "pending" until an executor reports back

    # schema-reserved: nothing produces these yet (see module docstring)
    request_id: Optional[str] = None    # link to originating ActionRequest
    goal: Optional[str] = None
    intent: Optional[str] = None
    policy_id: Optional[str] = None
    approval_ref: Optional[str] = None
    receipt_ref: Optional[str] = None

    # graph edges — hash-covered. Only "follows" is produced today.
    # New edge types may be added ONLY when a component produces them.
    edges: List[Dict[str, str]] = field(default_factory=list)

    # chain
    timestamp: float = field(default_factory=time.time)
    prev_hash: str = GENESIS_HASH
    record_hash: str = ""

    # ------------------------------------------------------------------

    def payload(self) -> Dict[str, Any]:
        """Everything covered by the hash, in canonical order."""
        return {
            "kind": self.kind,
            "protocol_version": self.protocol_version,
            "decision_id": self.decision_id,
            "parent_decision": self.parent_decision,
            "agent_id": self.agent_id,
            "capability": self.capability,
            "decision": self.decision,
            "triggered_by": self.triggered_by,
            "reason": self.reason,
            "severity": self.severity,
            "drift_score": self.drift_score,
            "evidence": self.evidence,
            "evidence_strength": self.evidence_strength,
            "arguments_digest": self.arguments_digest,
            "outcome": self.outcome,
            "request_id": self.request_id,
            "goal": self.goal,
            "intent": self.intent,
            "policy_id": self.policy_id,
            "approval_ref": self.approval_ref,
            "receipt_ref": self.receipt_ref,
            "edges": self.edges,
            "timestamp": self.timestamp,
            "prev_hash": self.prev_hash,
        }

    def compute_hash(self) -> str:
        canonical = json.dumps(
            self.payload(),
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    def apply_chain(self, prev_hash: str) -> "DecisionRecord":
        self.prev_hash = prev_hash
        return self.seal()

    def seal(self) -> "DecisionRecord":
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


def _digest_arguments(arguments: Dict[str, Any]) -> str:
    canonical = json.dumps(
        arguments,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def build_record(
    action: AgentAction,
    result: DecisionResult,
    *,
    parent_decision: Optional[str] = None,
    prev_hash: str = GENESIS_HASH,
    request_id: Optional[str] = None,
    anchor_hash: Optional[str] = None,
) -> DecisionRecord:
    """Reduce (AgentAction, DecisionResult) to a sealed DecisionRecord."""
    result_dict = result.to_dict()
    return DecisionRecord(
        decision_id=str(uuid.uuid4()),
        parent_decision=parent_decision,
        agent_id=action.agent_id,
        capability=action.capability,
        decision=result_dict["decision"],
        triggered_by=result_dict["triggered_by"],
        reason=result_dict["reason"],
        severity=result_dict["severity"],
        drift_score=result_dict["drift_score"],
        evidence=result_dict["evidence"],
        evidence_strength=result_dict["evidence_strength"],
        arguments_digest=_digest_arguments(action.arguments),
        outcome="pending",
        request_id=request_id,
        edges=(
            [{"type": "follows", "target": parent_decision}]
            if parent_decision is not None
            else []
        ),
    ).apply_chain(
        anchor_hash if (parent_decision is None and anchor_hash is not None)
        else prev_hash
    )
