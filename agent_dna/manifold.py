"""
Capability Manifold Learning (CML).

The manifold is Agent DNA's learned model of *what normal looks like* for an
agent. It is deliberately built from simple, inspectable statistics rather than a
black box — in regulated buyers (BFSI, healthcare) "why did you flag this?" must
have a one-sentence answer, and an opaque embedding cannot give one.

What it learns, per agent:
  * capability vocabulary + frequency  (which tools the agent normally uses)
  * per-capability argument feature distributions:
      - categorical features -> the set of values ever seen
      - numeric features     -> running mean / stdev / min / max
  * inter-action timing (to spot bursts)

The manifold is *advisory*. It produces evidence, not verdicts. See advisory.py
for the enforcement boundary.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Tuple

from .trace import AgentAction, ExecutionTrace

# A FeatureExtractor turns an action's raw arguments into a flat dict of
# features. Values that are int/float are treated as numeric; everything else is
# treated as categorical (stringified). Register capability-specific extractors
# to surface the features that matter for a given tool (recipient, amount, ...).
FeatureExtractor = Callable[[AgentAction], Dict[str, Any]]


def default_feature_extractor(action: AgentAction) -> Dict[str, Any]:
    """Generic, domain-agnostic extractor. Flattens one level of arguments."""
    feats: Dict[str, Any] = {}
    for key, value in action.arguments.items():
        if isinstance(value, bool):
            feats[key] = str(value)
        elif isinstance(value, (int, float)):
            feats[key] = float(value)
        elif isinstance(value, str):
            feats[key] = value
        elif isinstance(value, (list, tuple, set)):
            feats[f"{key}.count"] = float(len(value))
        # dicts and other types are ignored by the default extractor
    return feats


@dataclass
class _NumericStat:
    n: int = 0
    mean: float = 0.0
    m2: float = 0.0
    min: float = math.inf
    max: float = -math.inf

    def update(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (x - self.mean)
        self.min = min(self.min, x)
        self.max = max(self.max, x)

    @property
    def stdev(self) -> float:
        return math.sqrt(self.m2 / (self.n - 1)) if self.n > 1 else 0.0


@dataclass
class _CapabilityProfile:
    count: int = 0
    categorical: Dict[str, set] = field(default_factory=lambda: defaultdict(set))
    numeric: Dict[str, _NumericStat] = field(default_factory=lambda: defaultdict(_NumericStat))


class CapabilityManifold:
    """Learned trusted profile for a single logical agent identity."""

    def __init__(self, feature_extractor: FeatureExtractor | None = None) -> None:
        self.feature_extractor = feature_extractor or default_feature_extractor
        self.capability_counts: Counter = Counter()
        self.profiles: Dict[str, _CapabilityProfile] = defaultdict(_CapabilityProfile)
        self.intervals = _NumericStat()
        self.total_actions = 0
        self._fitted = False

    # ---- learning -------------------------------------------------------

    def fit(self, traces: Iterable[ExecutionTrace]) -> "CapabilityManifold":
        for trace in traces:
            self._observe_trace(trace)
        self._fitted = True
        return self

    def _observe_trace(self, trace: ExecutionTrace) -> None:
        prev_ts = None
        for action in trace.actions:
            self.capability_counts[action.capability] += 1
            self.total_actions += 1

            prof = self.profiles[action.capability]
            prof.count += 1

            for fname, fval in self.feature_extractor(action).items():
                if isinstance(fval, float):
                    prof.numeric[fname].update(fval)
                else:
                    prof.categorical[fname].add(str(fval))

            if prev_ts is not None:
                self.intervals.update(max(0.0, action.timestamp - prev_ts))

            prev_ts = action.timestamp

    # ---- queries --------------------------------------------------------

    @property
    def fitted(self) -> bool:
        return self._fitted

    def known_capability(self, capability: str) -> bool:
        return capability in self.capability_counts

    def capability_frequency(self, capability: str) -> float:
        if self.total_actions == 0:
            return 0.0
        return self.capability_counts.get(capability, 0) / self.total_actions

    def categorical_is_novel(
        self,
        capability: str,
        feature: str,
        value: str,
    ) -> bool:
        prof = self.profiles.get(capability)
        if not prof or feature not in prof.categorical:
            return False
        return str(value) not in prof.categorical[feature]

    def numeric_zscore(
        self,
        capability: str,
        feature: str,
        value: float,
    ) -> float | None:
        prof = self.profiles.get(capability)
        if not prof or feature not in prof.numeric:
            return None

        stat = prof.numeric[feature]

        if stat.stdev == 0.0:
            return 0.0 if value == stat.mean else math.inf

        return abs(value - stat.mean) / stat.stdev

    def numeric_bounds(
        self,
        capability: str,
        feature: str,
    ) -> Tuple[float, float] | None:
        prof = self.profiles.get(capability)
        if not prof or feature not in prof.numeric:
            return None

        stat = prof.numeric[feature]
        return (stat.min, stat.max)

    def summary(self) -> Dict[str, Any]:
        return {
            "total_actions": self.total_actions,
            "capabilities": dict(self.capability_counts),
            "mean_interval_s": round(self.intervals.mean, 3),
        }
