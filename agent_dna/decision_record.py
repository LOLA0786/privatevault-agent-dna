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
from typing import Any

from .decision import DecisionResult
from .trace import AgentAction

GENESIS_HASH = "0" * 64


PROTOCOL_VERSION = "drp/0.2"

# Algorithms every 0.2 record commits under, at seal time.
# Order is irrelevant: canonical() sorts. See spec/drp-0.2/COMMITMENTS.md.
COMMITMENT_ALGORITHMS = ("sha-256", "sha3-256")


@dataclass
class DecisionRecord:
    # identity / lineage
    kind: str = field(default="decision", init=False)   # record discriminator
    protocol_version: str = field(default=PROTOCOL_VERSION, init=False)
    decision_id: str
    parent_decision: str | None      # previous record for this agent (chain, not DAG — yet)
    agent_id: str
    capability: str

    # the decision itself
    decision: str                       # "allow" | "require_approval" | "block"
    triggered_by: str
    reason: str
    severity: str
    drift_score: float
    evidence: list[dict[str, Any]]
    evidence_strength: float

    # execution context
    arguments_digest: str               # sha256 of canonical arguments — never raw payloads
    outcome: str                        # "pending" until an executor reports back

    # schema-reserved: nothing produces these yet (see module docstring)
    request_id: str | None = None    # link to originating ActionRequest
    goal: str | None = None
    intent: str | None = None
    policy_id: str | None = None
    approval_ref: str | None = None
    receipt_ref: str | None = None

    # graph edges — hash-covered. Only "follows" is produced today.
    # New edge types may be added ONLY when a component produces them.
    edges: list[dict[str, str]] = field(default_factory=list)

    # chain
    timestamp: float = field(default_factory=time.time)
    prev_hash: str = GENESIS_HASH
    record_hash: str = ""
    commitments: dict[str, str] = field(default_factory=dict)

    # ------------------------------------------------------------------

    def payload(self) -> dict[str, Any]:
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

    def canonical_bytes(self) -> bytes:
        """The exact octets every commitment is computed over."""
        return json.dumps(
            self.payload(),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode()

    def compute_hash(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def compute_commitments(self) -> dict[str, str]:
        """One digest per algorithm, all over the identical canonical bytes."""
        raw = self.canonical_bytes()
        return {
            "sha-256": hashlib.sha256(raw).hexdigest(),
            "sha3-256": hashlib.sha3_256(raw).hexdigest(),
        }

    def signing_digest(self) -> str:
        """What the signature covers.

        DRP 0.1 signed record_hash. A commitment outside the signed
        surface is not load-bearing: an adversary with a SHA-256
        collision substitutes the payload and rewrites an unsigned
        commitments block to match. Signing over the commitments block
        means a SHA-2 collision still breaks the SHA3-256 entry.
        """
        if not self.commitments:
            raise ValueError("record is not sealed; no commitments to sign")
        canonical = json.dumps(
            self.commitments,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return hashlib.sha3_256(canonical.encode()).hexdigest()

    def apply_chain(self, prev_hash: str) -> DecisionRecord:
        self.prev_hash = prev_hash
        return self.seal()

    def seal(self) -> DecisionRecord:
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
        # unchecked claim, including one the verifier does not prefer.
        for algorithm, digest in self.commitments.items():
            if algorithm not in expected or expected[algorithm] != digest:
                return False
        return self.record_hash == self.commitments["sha-256"]

    def to_dict(self) -> dict[str, Any]:
        d = self.payload()
        d["record_hash"] = self.record_hash
        d["commitments"] = dict(self.commitments)
        return d


def _digest_arguments(arguments: dict[str, Any]) -> str:
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
    parent_decision: str | None = None,
    prev_hash: str = GENESIS_HASH,
    request_id: str | None = None,
    anchor_hash: str | None = None,
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
        # audit set 4: the grant this action executed under -- the
        # schema-reserved approval_ref finally populated
        approval_ref=getattr(result, "grant_id", None),
        # audit set 5 (P1-10): the fired customer-policy rule id
        policy_id=getattr(result, "policy_id", None),
        edges=(
            [{"type": "follows", "target": parent_decision}]
            if parent_decision is not None
            else []
        ),
    ).apply_chain(
        anchor_hash if (parent_decision is None and anchor_hash is not None)
        else prev_hash
    )
