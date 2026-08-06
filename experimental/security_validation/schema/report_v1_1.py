"""
Security Validation Report Schema v1.1

Canonical report model for benchmark execution.
"""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class BenchmarkInfo:
    schema_version: str = "1.1"
    benchmark_run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    runtime_target: str = ""
    scenario_id: str = ""


@dataclass
class AttackInfo:
    id: str
    name: str
    severity: str
    frameworks: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class Actor:
    agent: str
    agents: list[str] = field(default_factory=list)
    role: str = "agent"
    tenant: str = ""


@dataclass
class Decision:
    status: str
    security_score: float
    reason: str = ""


@dataclass
class BenchmarkReport:
    benchmark: BenchmarkInfo
    attack: AttackInfo
    attacker: Actor
    target: Actor
    decision: Decision

    evidence: list[Any] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
