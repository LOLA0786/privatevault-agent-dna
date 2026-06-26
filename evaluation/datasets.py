"""
Synthetic benchmark datasets for Agent DNA.

This module creates labelled datasets so we can measure precision, recall,
false positives, false negatives and detection latency.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

from agent_dna.adapters import (
    synthetic_compromised_trace,
    synthetic_normal_trace,
)
from agent_dna.trace import ExecutionTrace


@dataclass
class LabelledTrace:
    trace: ExecutionTrace
    malicious: bool


def normal_dataset(
    count: int = 100,
) -> List[LabelledTrace]:
    return [
        LabelledTrace(
            trace=synthetic_normal_trace(
                seed=i,
                loops=3,
            ),
            malicious=False,
        )
        for i in range(count)
    ]


def attack_dataset(
    count: int = 100,
) -> List[LabelledTrace]:
    return [
        LabelledTrace(
            trace=synthetic_compromised_trace(
                seed=i,
            ),
            malicious=True,
        )
        for i in range(count)
    ]


def benchmark_dataset(
    normal: int = 100,
    attacks: int = 100,
) -> List[LabelledTrace]:
    return (
        normal_dataset(normal)
        + attack_dataset(attacks)
    )

from evaluation.adversarial import (
    prompt_injection_trace,
    financial_fraud_trace,
    data_exfiltration_trace,
)


def adversarial_dataset() -> list[LabelledTrace]:
    traces = []

    for i in range(25):
        traces.append(
            LabelledTrace(
                prompt_injection_trace(seed=i),
                True,
            )
        )

    for i in range(25):
        traces.append(
            LabelledTrace(
                financial_fraud_trace(seed=100 + i),
                True,
            )
        )

    for i in range(25):
        traces.append(
            LabelledTrace(
                data_exfiltration_trace(seed=200 + i),
                True,
            )
        )

    return traces
