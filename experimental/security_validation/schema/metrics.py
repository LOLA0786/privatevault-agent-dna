"""
Benchmark metrics schema.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass
class RuntimeMetrics:
    latency_ms: float = 0.0
    execution_time_ms: float = 0.0
    tokens: int = 0
    cost_usd: float = 0.0

    def to_dict(self):
        return asdict(self)
