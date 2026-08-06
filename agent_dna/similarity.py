"""
Behavioral Identity Similarity Engine.

Compares two Agent DNA profiles using multiple behavioral dimensions rather than
a single hash.
"""

from __future__ import annotations

from dataclasses import dataclass

from .fingerprint import AgentFingerprint


@dataclass
class SimilarityResult:
    overall_similarity: float

    capability_similarity: float
    transition_similarity: float
    entropy_similarity: float

    added_capabilities: list[str]
    removed_capabilities: list[str]

    hash_match: bool
    risk: str

    def to_dict(self) -> dict:
        return {
            "overall_similarity": round(self.overall_similarity, 4),
            "capability_similarity": round(self.capability_similarity, 4),
            "transition_similarity": round(self.transition_similarity, 4),
            "entropy_similarity": round(self.entropy_similarity, 4),
            "added_capabilities": self.added_capabilities,
            "removed_capabilities": self.removed_capabilities,
            "hash_match": self.hash_match,
            "risk": self.risk,
        }


class SimilarityEngine:
    def compare(
        self,
        trusted: AgentFingerprint,
        candidate: AgentFingerprint,
    ) -> SimilarityResult:

        trusted_caps: set[str] = set(trusted.capability_counts.keys())

        candidate_caps: set[str] = set(candidate.capability_counts.keys())

        inter = len(trusted_caps & candidate_caps)
        union = max(len(trusted_caps | candidate_caps), 1)

        capability_similarity = inter / union

        trusted_trans = set(trusted.transitions)
        candidate_trans = set(candidate.transitions)

        inter = len(trusted_trans & candidate_trans)
        union = max(len(trusted_trans | candidate_trans), 1)

        transition_similarity = inter / union

        entropy_similarity = max(
            0.0,
            1.0 - abs(trusted.capability_entropy - candidate.capability_entropy) / 5.0,
        )

        overall = (
            capability_similarity * 0.40
            + transition_similarity * 0.40
            + entropy_similarity * 0.20
        )

        if overall >= 0.95:
            risk = "LOW"
        elif overall >= 0.80:
            risk = "MEDIUM"
        else:
            risk = "HIGH"

        return SimilarityResult(
            overall_similarity=overall,
            capability_similarity=capability_similarity,
            transition_similarity=transition_similarity,
            entropy_similarity=entropy_similarity,
            added_capabilities=sorted(candidate_caps - trusted_caps),
            removed_capabilities=sorted(trusted_caps - candidate_caps),
            hash_match=(trusted.behavior_hash == candidate.behavior_hash),
            risk=risk,
        )
