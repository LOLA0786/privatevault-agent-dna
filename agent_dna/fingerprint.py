"""
Behavioral fingerprint for Agent DNA.

Summarizes a learned behavioral profile into a stable identity that can be
versioned, compared and tracked over time.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Dict, List

from .dynamics import BehaviorDynamics
from .manifold import CapabilityManifold


@dataclass
class AgentFingerprint:
    agent_id: str

    trained_actions: int
    capabilities: int

    capability_entropy: float
    transition_entropy: float

    behavior_hash: str

    capability_counts: Dict[str, int]
    transitions: List[str]

    def to_dict(self) -> Dict:
        return {
            "agent_id": self.agent_id,
            "trained_actions": self.trained_actions,
            "capabilities": self.capabilities,
            "capability_entropy": round(self.capability_entropy, 4),
            "transition_entropy": round(self.transition_entropy, 4),
            "behavior_hash": self.behavior_hash,
            "capability_counts": self.capability_counts,
            "transitions": self.transitions,
        }


class FingerprintBuilder:

    def build(
        self,
        agent_id: str,
        manifold: CapabilityManifold,
        dynamics: BehaviorDynamics,
    ) -> AgentFingerprint:

        capability_entropy = self._capability_entropy(manifold)
        transition_entropy = self._transition_entropy(dynamics)

        payload = {
            "capabilities": dict(sorted(manifold.capability_counts.items())),
            "transitions": {
                k: dict(sorted(v.items()))
                for k, v in sorted(dynamics.transition_counts.items())
            },
        }

        digest = hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
            ).encode()
        ).hexdigest()

        return AgentFingerprint(
            agent_id=agent_id,
            trained_actions=manifold.total_actions,
            capabilities=len(manifold.capability_counts),
            capability_entropy=capability_entropy,
            transition_entropy=transition_entropy,
            behavior_hash=digest,
            capability_counts=dict(manifold.capability_counts),
            transitions=[
                f"{src}->{dst}"
                for src, mapping in dynamics.transition_counts.items()
                for dst in mapping.keys()
            ],
        )

    def _capability_entropy(
        self,
        manifold: CapabilityManifold,
    ) -> float:

        total = manifold.total_actions

        if total == 0:
            return 0.0

        entropy = 0.0

        for count in manifold.capability_counts.values():
            p = count / total
            entropy -= p * math.log2(p)

        return entropy

    def _transition_entropy(
        self,
        dynamics: BehaviorDynamics,
    ) -> float:

        total = sum(dynamics.prefix_totals.values())

        if total == 0:
            return 0.0

        entropy = 0.0

        for mapping in dynamics.transition_counts.values():
            for count in mapping.values():
                p = count / total
                entropy -= p * math.log2(p)

        return entropy
