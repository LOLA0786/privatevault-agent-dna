"""
Evaluation metrics for Agent DNA.

These metrics intentionally mirror what security teams and research papers
expect: precision, recall, F1, false-positive rate, false-negative rate and
detection latency.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class EvaluationResult:
    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0
    latency_sum: int = 0
    detections: int = 0

    @property
    def precision(self) -> float:
        d = self.true_positive + self.false_positive
        return self.true_positive / d if d else 0.0

    @property
    def recall(self) -> float:
        d = self.true_positive + self.false_negative
        return self.true_positive / d if d else 0.0

    @property
    def f1(self) -> float:
        p = self.precision
        r = self.recall
        return (2 * p * r / (p + r)) if (p + r) else 0.0

    @property
    def false_positive_rate(self) -> float:
        d = self.false_positive + self.true_negative
        return self.false_positive / d if d else 0.0

    @property
    def false_negative_rate(self) -> float:
        d = self.false_negative + self.true_positive
        return self.false_negative / d if d else 0.0

    @property
    def average_detection_latency(self) -> float:
        return self.latency_sum / self.detections if self.detections else 0.0

    def report(self) -> str:
        return f"""
========================================
Agent DNA Evaluation
========================================

Precision              {self.precision:.2%}
Recall                 {self.recall:.2%}
F1 Score               {self.f1:.2%}

False Positive Rate    {self.false_positive_rate:.2%}
False Negative Rate    {self.false_negative_rate:.2%}

Average Detection
Latency                {self.average_detection_latency:.2f} actions
"""
