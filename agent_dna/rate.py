"""
Burst / Rate Anomaly Detection.

Detects behavioral drift caused by abnormal execution speed.
"""

from __future__ import annotations

from dataclasses import dataclass

from .manifold import CapabilityManifold


@dataclass
class RateSignal:
    score: float
    reason: str


class RateAnomalyDetector:

    def __init__(self, manifold: CapabilityManifold):
        self.manifold = manifold

    def score(self, interval_seconds: float) -> RateSignal:

        mean = self.manifold.intervals.mean
        stdev = self.manifold.intervals.stdev

        if mean == 0:
            return RateSignal(
                score=0.0,
                reason="No timing profile available.",
            )

        if stdev == 0:
            stdev = max(mean * 0.10, 1.0)

        #
        # Faster than expected is suspicious.
        #

        if interval_seconds >= mean:
            return RateSignal(
                score=0.0,
                reason="Execution rate within trusted profile.",
            )

        z = (mean - interval_seconds) / stdev

        score = min(
            1.0,
            max(
                0.0,
                z / 6.0,
            ),
        )

        return RateSignal(
            score=score,
            reason=(
                f"Observed interval {interval_seconds:.2f}s "
                f"is significantly faster than learned baseline "
                f"({mean:.2f}s)."
            ),
        )
