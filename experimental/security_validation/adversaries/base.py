"""
Base adversary interface.

All adversarial agents inherit from this class.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC


class BaseAdversary(ABC):
    attack_id: str = "UNKNOWN"

    attack_name: str = "Unnamed Attack"

    framework_mappings: dict = {}

    severity: str = "Medium"

    schema_version: str = "1.0"

    # Default attacking agent (override in subclasses if needed)
    attacker_agent: str = "red-team-agent"

    # Multi-agent attacks may override this instead
    attacker_agents: list[str] = []

    @abstractmethod
    def run(self, target_agent: str) -> dict:
        """
        Execute attack against target.
        Must return structured result.
        """
        raise NotImplementedError

    def metadata(self) -> dict:

        return {
            "attack_id": self.attack_id,
            "attack_name": self.attack_name,
            "severity": self.severity,
            "framework_mappings": self.framework_mappings,
        }

    def required_evidence(self) -> list[str]:

        return [
            "decision_receipt",
            "merkle_root",
            "runtime_trace",
        ]

    def attack_context(self, target_agent: str) -> dict:
        """
        Standard metadata attached to every benchmark result.
        """
        import uuid
        from datetime import datetime

        return {
            "schema_version": self.schema_version,
            "benchmark_run_id": str(uuid.uuid4()),
            "attack_timestamp": datetime.now(UTC).isoformat(),
            "attack": {
                "id": self.attack_id,
                "name": self.attack_name,
                "severity": self.severity,
            },
            "attacker": {
                "agent": self.attacker_agent,
                "agents": self.attacker_agents,
            },
            "target": {
                "agent": target_agent,
            },
        }
