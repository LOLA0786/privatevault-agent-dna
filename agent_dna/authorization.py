"""
Enterprise Authorization Policy.

A capability grant is only valid if its deployment context matches.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional


@dataclass
class CapabilityGrant:
    capability: str
    approved_by: str
    ticket: str

    environment: str = "prod"

    version: str = "*"

    expires_at: Optional[datetime] = None


class AuthorizationPolicy:

    def __init__(self) -> None:
        self._grants: Dict[str, Dict[str, CapabilityGrant]] = {}

    def grant(
        self,
        agent_id: str,
        capability: str,
        approved_by: str,
        ticket: str,
        environment: str = "prod",
        version: str = "*",
        expires_at: Optional[datetime] = None,
    ) -> None:

        self._grants.setdefault(agent_id, {})

        self._grants[agent_id][capability] = CapabilityGrant(
            capability=capability,
            approved_by=approved_by,
            ticket=ticket,
            environment=environment,
            version=version,
            expires_at=expires_at,
        )

    def lookup(
        self,
        agent_id: str,
        capability: str,
    ) -> Optional[CapabilityGrant]:

        return self._grants.get(
            agent_id,
            {},
        ).get(capability)

    def is_authorized(
        self,
        agent_id: str,
        capability: str,
        *,
        environment: str = "prod",
        version: str = "*",
    ) -> bool:

        grant = self.lookup(
            agent_id,
            capability,
        )

        if grant is None:
            return False

        if grant.environment != environment:
            return False

        if grant.version not in ("*", version):
            return False

        if (
            grant.expires_at is not None
            and datetime.utcnow() > grant.expires_at
        ):
            return False

        return True
