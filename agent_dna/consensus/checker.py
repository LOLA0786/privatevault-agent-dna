"""
ConsensusChecker — evidence-gated multi-agent quorum check.

Wraps SecureQuorum. Same evidence-honesty discipline as UAAL (L0) and
CostAnomalyChecker: if evidence["consensus"] is absent, the check is
SKIPPED, never silently passed. Never blocks -- ceiling is
REQUIRE_APPROVAL, same as authorization/economics/drift, because a
quorum shortfall is a governance signal, not a proven security
violation the way a tampered amount is.

Evidence shape:
    evidence["consensus"] = {
        "action_id": str,
        "threshold": float,               # default 0.67
        "votes": [
            {"agent_id": str, "vote": "APPROVE"|"REJECT",
             "signature": str, "message_hash": str},
            ...
        ],
        "trust_scores": {agent_id: float},  # optional, default 0.5
    }
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .secure_quorum import SecureQuorum, TrustRegistry


@dataclass
class ConsensusResult:
    flagged: bool
    reason: str = ""
    checks_run: List[str] = field(default_factory=list)
    checks_skipped: List[str] = field(default_factory=list)


class ConsensusChecker:
    DEFAULT_THRESHOLD = 0.67

    def check(self, evidence: Optional[Dict[str, Any]] = None) -> ConsensusResult:
        consensus = (evidence or {}).get("consensus")
        if consensus is None:
            return ConsensusResult(flagged=False, checks_skipped=["quorum"])

        action_id = consensus.get("action_id", "unspecified-action")
        threshold = consensus.get("threshold", self.DEFAULT_THRESHOLD)
        votes = consensus.get("votes", [])
        trust_scores = consensus.get("trust_scores", {})

        registry = TrustRegistry()
        for agent_id, score in trust_scores.items():
            registry.set_score(agent_id, score)

        quorum = SecureQuorum(threshold=threshold, trust_registry=registry)
        for v in votes:
            quorum.submit_vote(
                action_id, v["agent_id"], v["vote"],
                v["signature"], v["message_hash"],
            )

        approved = quorum.check_quorum(action_id)
        if approved:
            return ConsensusResult(flagged=False, checks_run=["quorum"])

        return ConsensusResult(
            flagged=True,
            reason=(
                f"quorum_shortfall: action {action_id!r} did not reach "
                f"threshold {threshold} across {len(votes)} submitted vote(s) "
                f"(unsigned, unregistered, or dissenting votes contribute zero)"
            ),
            checks_run=["quorum"],
        )
