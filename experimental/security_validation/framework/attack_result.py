from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AttackResult:
    attack_name: str
    status: str
    security_score: float

    reason: str = ""

    evidence: list[Any] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    raw_result: dict[str, Any] = field(default_factory=dict)

    def passed(self) -> bool:
        return self.status.lower() in ("blocked", "success", "passed")

    def failed(self) -> bool:
        return not self.passed()
