from collections import Counter


class MetricsExporter:
    def __init__(self) -> None:
        self.decisions: Counter = Counter()
        self.drift_scores: list[float] = []
        self.block_reasons: Counter = Counter()

    def record(self, decision_str: str, drift_score: float, reason: str = "") -> None:
        self.decisions[decision_str] += 1
        self.drift_scores.append(drift_score)
        if decision_str.lower() == "block":
            self.block_reasons[reason] += 1

    def summary(self) -> dict:
        return {
            "total_decisions": sum(self.decisions.values()),
            "verdict_distribution": dict(self.decisions),
            "avg_drift": sum(self.drift_scores) / max(len(self.drift_scores), 1),
            "block_reasons": dict(self.block_reasons),
        }
