from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AttackResult:
    attack_id: str
    attack_name: str
    status: str
    severity: str

    score: float = 0.0
    latency_ms: float = 0.0

    policy: str | None = None
    receipt_hash: str | None = None
    merkle_root: str | None = None

    evidence: list[Any] = field(default_factory=list)

    frameworks: dict[str, list[str]] = field(default_factory=dict)

    metadata: dict[str, Any] = field(default_factory=dict)

    def passed(self) -> bool:
        return self.status.upper() in {"BLOCKED", "DETECTED", "CONTAINED"}
