"""
Behavior Dynamics Model (BDM).

The manifold knows *which* capabilities are normal; dynamics knows *in what
order*. A read-enrich-update-email loop is benign; the same agent jumping
straight from "read customer record" to "initiate wire" is not — even though
every individual capability might be in-vocabulary.

We model this as a Laplace-smoothed first-order Markov chain over the capability
sequence, per agent. Surprise for a transition is its self-information
-log2 P(curr | prev). Unseen transitions get high surprise via smoothing. During
fit we record a normalisation reference (95th-percentile training surprise) so
the scorer can map raw surprise onto a 0..1 scale.
"""

from __future__ import annotations

import math
from collections import defaultdict
from collections.abc import Iterable

from .trace import ExecutionTrace

_START = "<START>"


class BehaviorDynamics:
    def __init__(self, smoothing: float = 1.0) -> None:
        self.smoothing = smoothing
        self.transition_counts: dict[str, dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        self.prefix_totals: dict[str, int] = defaultdict(int)
        self.vocab: set = set()

        # Highest transition-surprise actually observed in training.
        self.ceil_surprise: float = 1.0
        self._fitted = False

    def fit(self, traces: Iterable[ExecutionTrace]) -> BehaviorDynamics:
        traces = list(traces)

        for trace in traces:
            prev = _START
            for cap in trace.capabilities:
                self.transition_counts[prev][cap] += 1
                self.prefix_totals[prev] += 1
                self.vocab.add(cap)
                prev = cap

        self._fitted = True
        self.ceil_surprise = self._compute_ceiling(traces)
        return self

    def _compute_ceiling(self, traces: list[ExecutionTrace]) -> float:
        ceil = 0.0

        for trace in traces:
            prev = _START
            for cap in trace.capabilities:
                ceil = max(ceil, self.surprise(prev, cap))
                prev = cap

        return max(ceil, 1e-6)

    def transition_probability(self, prev: str, curr: str) -> float:
        vocab_size = max(len(self.vocab), 1)

        numerator = self.transition_counts[prev].get(curr, 0) + self.smoothing

        denominator = self.prefix_totals.get(prev, 0) + self.smoothing * vocab_size

        return numerator / denominator

    def surprise(self, prev: str, curr: str) -> float:
        return -math.log2(self.transition_probability(prev, curr))

    @property
    def fitted(self) -> bool:
        return self._fitted
