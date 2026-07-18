"""
Base adversary interface.

All adversarial agents inherit from this class.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List


class BaseAdversary(ABC):

    attack_id: str = "UNKNOWN"

    attack_name: str = "Unnamed Attack"

    framework_mappings: Dict = {}

    severity: str = "Medium"

    schema_version: str = "1.0"

    # Default attacking agent (override in subclasses if needed)
    attacker_agent: str = "red-team-agent"

    # Multi-agent attacks may override this instead
    attacker_agents: List[str] = []

    @abstractmethod
    def run(self, target_agent: str) -> Dict:
        """
        Execute attack against target.
        Must return structured result.
        """
        raise NotImplementedError

    def metadata(self) -> Dict:

        return {
            "attack_id": self.attack_id,
            "attack_name": self.attack_name,
            "severity": self.severity,
            "framework_mappings": self.framework_mappings,
        }

    def required_evidence(self) -> List[str]:

        return [
            "decision_receipt",
            "merkle_root",
            "runtime_trace",
        ]

    def attack_context(self, target_agent: str) -> Dict:
        """
        Standard metadata attached to every benchmark result.
        """
        from datetime import datetime, timezone
        import uuid

        return {
            "schema_version": self.schema_version,
            "benchmark_run_id": str(uuid.uuid4()),
            "attack_timestamp": datetime.now(timezone.utc).isoformat(),

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
