"""
Aggregate analytics — anonymized drift and verdict distributions.
Produces cross-organization statistical reports without
exposing individual agent actions or identities.
"""

from collections import Counter


class AggregateAnalytics:
    """
    Computes anonymized statistics from decision streams.
    No agent_id, no capability payload, no raw arguments.
    Only: verdict counts, drift score bins, invariant hits.
    """

    def __init__(self):
        self.verdict_counts: Counter = Counter()
        self.drift_bins: dict[str, int] = {
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0,
        }
        self.invariant_hits: Counter = Counter()

    def record(self, verdict: str, drift_score: float, invariant_name: str = ""):
        self.verdict_counts[verdict] += 1
        if drift_score < 0.3:
            self.drift_bins["low"] += 1
        elif drift_score < 0.6:
            self.drift_bins["medium"] += 1
        elif drift_score < 0.8:
            self.drift_bins["high"] += 1
        else:
            self.drift_bins["critical"] += 1
        if invariant_name:
            self.invariant_hits[invariant_name] += 1

    def global_summary(self) -> dict:
        total = sum(self.verdict_counts.values()) or 1
        return {
            "total_decisions": total,
            "verdict_distribution": dict(self.verdict_counts),
            "block_rate": self.verdict_counts.get("BLOCK", 0) / total,
            "approval_rate": self.verdict_counts.get("ALLOW", 0) / total,
            "drift_distribution": self.drift_bins,
            "top_invariants": dict(self.invariant_hits.most_common(5)),
        }
