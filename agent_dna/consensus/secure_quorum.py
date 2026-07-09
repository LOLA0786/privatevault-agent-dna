"""
Vendored from PrivateVault.ai's coordination/mesh/secure_quorum.py
and trust_registry.py. Logic preserved; signature verification now
constant-time (see signing.py). No tests existed for this in the
source repo prior to vendoring — the one test file in that tree
(test_full_flow.py) fails at import due to a missing dependency
(pv_mesh_enforcer) and has never successfully run.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from .signing import verify_signature


class TrustRegistry:
    def __init__(self) -> None:
        self.scores: Dict[str, float] = {}

    def set_score(self, agent_id: str, score: float) -> None:
        self.scores[agent_id] = score

    def get(self, agent_id: str, default: float = 0.5) -> float:
        return self.scores.get(agent_id, default)


class SecureQuorum:
    def __init__(self, threshold: float, trust_registry: TrustRegistry) -> None:
        self.threshold = threshold
        self.votes: Dict[str, List[dict]] = defaultdict(list)
        self.trust_registry = trust_registry

    def submit_vote(
        self, action_id: str, agent_id: str, vote: str,
        signature: str, message_hash: str,
    ) -> None:
        self.votes[action_id].append({
            "agent": agent_id, "vote": vote,
            "signature": signature, "hash": message_hash,
        })

    def check_quorum(self, action_id: str) -> bool:
        score = 0.0
        for v in self.votes[action_id]:
            if not verify_signature(v["agent"], v["hash"], v["signature"]):
                continue
            if v["vote"] == "APPROVE":
                score += self.trust_registry.get(v["agent"])
        return score >= self.threshold
