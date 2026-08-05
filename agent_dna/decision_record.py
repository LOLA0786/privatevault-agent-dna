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
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from .action_v01 import execution_action_digest
from .decision import DecisionResult
from .trace import AgentAction

GENESIS_HASH = "0" * 64


DRP_V01 = "drp/0.1"
DRP_V02 = "drp/0.2"
KNOWN_PROTOCOL_VERSIONS = frozenset({DRP_V01, DRP_V02})

# New records default to the version that binds an execution action.
CURRENT_PROTOCOL_VERSION = DRP_V02

# Retained: existing imports refer to this name.
PROTOCOL_VERSION = DRP_V01

_SHA256_PREFIXED = re.compile(r"sha256:[0-9a-f]{64}")


@dataclass
class DecisionRecord:
    # identity / lineage
    kind: str = field(default="decision", init=False)   # record discriminator
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

    # Keyword-only, so existing positional constructor order is unchanged.
    # protocol_version is REQUIRED: omitting it must never silently produce
    # a legacy record. Every producer states whether it is creating a bound
    # (drp/0.2) or legacy (drp/0.1) record.
    protocol_version: str = field(kw_only=True)
    # May default to None: v0.1 requires it absent. The version never
    # follows from the digest's presence -- that would make a missing
    # binding look like a legitimate downgrade.
    action_digest: str | None = field(default=None, kw_only=True)

    # ------------------------------------------------------------------

    def __post_init__(self) -> None:
        check_version_invariant(self.protocol_version, self.action_digest)

    def payload(self) -> dict[str, Any]:
        """Everything covered by the hash, in canonical order.

        drp/0.2 adds action_digest and nothing else, so a v0.1 payload is
        byte-identical to what it was before v0.2 existed.
        """
        check_version_invariant(self.protocol_version, self.action_digest)
        body = {
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
        if self.protocol_version == DRP_V02:
            # Guaranteed by the invariant above; restated for the type
            # checker, which cannot see through the helper.
            assert self.action_digest is not None
            body["action_digest"] = self.action_digest
        return body

    def compute_hash(self) -> str:
        canonical = json.dumps(
            self.payload(),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    def apply_chain(self, prev_hash: str) -> DecisionRecord:
        self.prev_hash = prev_hash
        return self.seal()

    def seal(self) -> DecisionRecord:
        self.record_hash = self.compute_hash()
        return self

    def verify(self) -> bool:
        """False, never an exception: a caller checking a record it did
        not build should get a verdict, not a traceback."""
        try:
            check_version_invariant(self.protocol_version, self.action_digest)
        except ValueError:
            return False
        return (
            self.record_hash != ""
            and self.record_hash == self.compute_hash()
        )

    def to_dict(self) -> dict[str, Any]:
        d = self.payload()
        d["record_hash"] = self.record_hash
        return d


def check_version_invariant(
    protocol_version: str,
    action_digest: str | None,
) -> None:
    """The only legal version/digest combinations.

    Called at construction, payload generation, sealing, verification and
    deserialization, so a record cannot be mutated into an invalid pair
    after it was built. The version is never inferred from the digest: a
    drp/0.2 record missing its binding is rejected, not downgraded.
    """
    if protocol_version not in KNOWN_PROTOCOL_VERSIONS:
        raise ValueError(
            f"unknown protocol_version {protocol_version!r}; "
            f"this build implements {sorted(KNOWN_PROTOCOL_VERSIONS)}"
        )

    if protocol_version == DRP_V01:
        if action_digest is not None:
            raise ValueError(
                "drp/0.1 records carry no action_digest; a bound record "
                "must declare drp/0.2"
            )
        return

    # drp/0.2
    if action_digest is None:
        raise ValueError(
            "drp/0.2 requires an action_digest; a missing binding is not "
            "a downgrade to drp/0.1"
        )
    if not _SHA256_PREFIXED.fullmatch(action_digest):
        raise ValueError(
            f"malformed action_digest {action_digest!r}; "
            'expected "sha256:" followed by 64 lowercase hex characters'
        )


def _digest_arguments(arguments: dict[str, Any]) -> str:
    canonical = json.dumps(
        arguments,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _build_record(
    action: AgentAction,
    result: DecisionResult,
    *,
    protocol_version: str,
    action_digest: str | None,
    parent_decision: str | None,
    prev_hash: str,
    request_id: str | None,
    anchor_hash: str | None,
) -> DecisionRecord:
    """The single construction and sealing path.

    Both public builders route through here so the field mapping exists
    once, and so a record is constructed in its final protocol shape
    before its first seal. Nothing upgrades a sealed record: a hash is
    content-addressed, and a transitional artifact could be observed by
    anything later added to this function.
    """
    result_dict = result.to_dict()
    return DecisionRecord(
        protocol_version=protocol_version,
        action_digest=action_digest,
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


def build_record(
    action: AgentAction,
    result: DecisionResult,
    *,
    parent_decision: str | None = None,
    prev_hash: str = GENESIS_HASH,
    request_id: str | None = None,
    anchor_hash: str | None = None,
) -> DecisionRecord:
    """Reduce (AgentAction, DecisionResult) to a sealed drp/0.1 record.

    Legacy: the record commits to an arguments digest but not to the
    canonical execution action, so it can be audited but must never
    authorize execution.
    """
    return _build_record(
        action,
        result,
        protocol_version=DRP_V01,
        action_digest=None,
        parent_decision=parent_decision,
        prev_hash=prev_hash,
        request_id=request_id,
        anchor_hash=anchor_hash,
    )


def build_record_v02(
    action: AgentAction,
    result: DecisionResult,
    *,
    execution_action: dict[str, Any],
    parent_decision: str | None = None,
    prev_hash: str = GENESIS_HASH,
    request_id: str | None = None,
    anchor_hash: str | None = None,
) -> DecisionRecord:
    """A sealed drp/0.2 record bound to an exact canonical execution action.

    There is deliberately no action_digest parameter. The digest is
    computed here from the complete action, so a caller cannot present a
    digest for one action while the permit later names another.
    """
    return _build_record(
        action,
        result,
        protocol_version=DRP_V02,
        action_digest=execution_action_digest(execution_action),
        parent_decision=parent_decision,
        prev_hash=prev_hash,
        request_id=request_id,
        anchor_hash=anchor_hash,
    )
