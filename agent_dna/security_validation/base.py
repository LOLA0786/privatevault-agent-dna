from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from .results import AttackResult


class BaseAdversary(ABC):
    attack_id: str = ""
    name: str = ""
    severity: str = "Unknown"

    def prepare(self) -> None:
        pass

    @abstractmethod
    def execute(self, runtime: Any) -> AttackResult:
        ...

    def verify(self, result: AttackResult) -> bool:
        return True

    def cleanup(self) -> None:
        pass
