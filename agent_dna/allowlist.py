"""
Authorized Capability Registry.

Distinguishes expected behavioral evolution from unexpected behavioral drift.

Example

v1
----
crm.read
crm.update

v2 (approved deployment)
------------------------
+ payments.initiate_wire

Agent DNA should NOT flag that capability as malicious because it was
explicitly granted through a trusted deployment process.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass, field


@dataclass
class CapabilityRegistry:
    """
    Records capabilities that have been explicitly approved for an agent.
    """

    def __init__(self, *args, **kwargs):
        warnings.warn(
            "CapabilityRegistry is deprecated (audit set 4); use "
            "agent_dna.grants.GrantRegistry",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__()

    grants: dict[str, set[str]] = field(default_factory=dict)

    def grant(
        self,
        agent_id: str,
        capability: str,
    ) -> None:

        self.grants.setdefault(
            agent_id,
            set(),
        ).add(capability)

    def revoke(
        self,
        agent_id: str,
        capability: str,
    ) -> None:

        self.grants.setdefault(
            agent_id,
            set(),
        ).discard(capability)

    def is_authorized(
        self,
        agent_id: str,
        capability: str,
    ) -> bool:

        return capability in self.grants.get(
            agent_id,
            set(),
        )

    def authorized_capabilities(
        self,
        agent_id: str,
    ) -> set[str]:

        return set(
            self.grants.get(
                agent_id,
                set(),
            )
        )
