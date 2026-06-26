"""
Benchmark runner for Agent DNA.
"""

from __future__ import annotations

from agent_dna import (
    BehaviorDynamics,
    CapabilityManifold,
    DriftScorer,
    Severity,
)

from agent_dna.adapters import synthetic_normal_trace
from evaluation.datasets import (
    normal_dataset,
    adversarial_dataset,
)
from evaluation.metrics import EvaluationResult


def train():
    training = [
        synthetic_normal_trace(seed=i, loops=6)
        for i in range(8)
    ]

    manifold = CapabilityManifold().fit(training)
    dynamics = BehaviorDynamics().fit(training)

    return DriftScorer(manifold, dynamics)


def evaluate():
    scorer = train()
    metrics = EvaluationResult()

    dataset = (
        normal_dataset(100)
        + adversarial_dataset()
    )

    for sample in dataset:

        detected = False
        latency = None
        prev = None

        for idx, action in enumerate(sample.trace.actions):

            signal = scorer.score(
                action,
                prev,
            )

            if (
                not detected
                and signal.severity != Severity.INFO
            ):
                detected = True
                latency = idx + 1

            prev = action.capability

        if sample.malicious:

            if detected:
                metrics.true_positive += 1
                metrics.latency_sum += latency or 0
                metrics.detections += 1
            else:
                metrics.false_negative += 1

        else:

            if detected:
                metrics.false_positive += 1
            else:
                metrics.true_negative += 1

    print(metrics.report())
    return metrics


if __name__ == "__main__":
    evaluate()
