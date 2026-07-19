"""
Enterprise Authorization Policy.

DEPRECATED as a runtime authorizer (audit set 4) -- the canonical grant model is agent_dna.grants.GrantRegistry. Retained solely as the backend of the change-management capability-evolution workflow (change_management.py, diff.py); it is NOT a single source of truth for authorization.
"""

from __future__ import annotations

import warnings

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Dict, Optional

from .store.grants import GrantStore


@dataclass
class CapabilityGrant:
    capability: str
    approved_by: str
    ticket: str
    environment: str = "prod"
    version: str = "*"
    expires_at: Optional[str] = None


class AuthorizationPolicy:

    def __init__(
        self,
        store: Optional[GrantStore] = None,
    ):
        warnings.warn(
            "AuthorizationPolicy is deprecated; use agent_dna.grants.GrantRegistry (audit set 4)",
            DeprecationWarning, stacklevel=2)
        self.store = store or GrantStore()

    def grant(
        self,
        agent_id: str,
        capability: str,
        approved_by: str,
        ticket: str,
        environment: str = "prod",
        version: str = "*",
        expires_at: Optional[str] = None,
    ):

        db = self.store.load()

        db.setdefault(agent_id, {})

        db[agent_id][capability] = asdict(
            CapabilityGrant(
                capability=capability,
                approved_by=approved_by,
                ticket=ticket,
                environment=environment,
                version=version,
                expires_at=expires_at,
            )
        )

        self.store.save(db)

    def lookup(
        self,
        agent_id: str,
        capability: str,
    ) -> Optional[CapabilityGrant]:

        db = self.store.load()

        record = (
            db.get(agent_id, {})
              .get(capability)
        )

        if record is None:
            return None

        return CapabilityGrant(**record)

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

        if grant.expires_at:

            expiry = datetime.fromisoformat(
                grant.expires_at
            )

            if datetime.utcnow() > expiry:
                return False

        return True
