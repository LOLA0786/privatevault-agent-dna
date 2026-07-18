"""
Security Validation Report Schema v1.1

Canonical report model for benchmark execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List
import uuid


@dataclass
class BenchmarkInfo:
    schema_version: str = "1.1"
    benchmark_run_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    runtime_target: str = ""
    scenario_id: str = ""


@dataclass
class AttackInfo:
    id: str
    name: str
    severity: str
    frameworks: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class Actor:
    agent: str
    agents: List[str] = field(default_factory=list)
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

    evidence: List[Any] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
