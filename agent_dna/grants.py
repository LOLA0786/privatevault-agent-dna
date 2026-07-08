"""
CapabilityGrant — grants with lifecycle (expiry, revocation, budget).

Replaces bare allowlist authorization with explicit grant objects that
answer WHY authorization failed, not just whether. Built in direct
response to external review (A.P., 2026-07): "no revocation or
time-boxing shown" and "L2 is the thinnest box carrying the most
weight."

Shipped here: expiry, revocation, per-grant budget, failure reasons,
grant_ref lineage into DecisionRecords.
Explicit roadmap (NOT shipped): delegation chains, mid-session
rescoping, approval-token binding, consent workflows.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple


@dataclass
class CapabilityGrant:
    grant_id: str
    agent_id: str
    capability: str
    granted_by: str
    expires_at: Optional[float] = None      # epoch seconds; None = no expiry
    budget: Optional[float] = None          # cumulative amount ceiling; None = unmetered
    spent: float = 0.0
    revoked: bool = False
    revoked_at: Optional[float] = None
    revoked_by: Optional[str] = None
    created_at: float = field(default_factory=time.time)


class GrantRegistry:
    """In-memory grant store + authorizer. Same is_authorized contract
    as the allowlist authorizer (drop-in), plus an explain() that names
    the failing condition and the grant involved."""

    def __init__(self) -> None:
        self._grants: Dict[str, CapabilityGrant] = {}

    # ---- lifecycle -----------------------------------------------------

    def grant(
        self,
        *,
        agent_id: str,
        capability: str,
        granted_by: str,
        expires_at: Optional[float] = None,
        budget: Optional[float] = None,
    ) -> CapabilityGrant:
        g = CapabilityGrant(
            grant_id=f"grant-{uuid.uuid4()}",
            agent_id=agent_id,
            capability=capability,
            granted_by=granted_by,
            expires_at=expires_at,
            budget=budget,
        )
        self._grants[g.grant_id] = g
        return g

    def revoke(self, grant_id: str, *, revoked_by: str) -> CapabilityGrant:
        g = self._grants[grant_id]
        g.revoked = True
        g.revoked_at = time.time()
        g.revoked_by = revoked_by
        return g

    # ---- evaluation ------------------------------------------------------

    def _find(self, agent_id: str, capability: str):
        return [
            g for g in self._grants.values()
            if g.agent_id == agent_id and g.capability == capability
        ]

    def explain(
        self,
        agent_id: str,
        capability: str,
        amount: Optional[float] = None,
        now: Optional[float] = None,
    ) -> Tuple[bool, str, Optional[str]]:
        """(authorized, reason, grant_id). Reason names the specific
        failing condition — 'grant expired', 'grant revoked', 'budget
        exceeded' — never just 'no'."""
        now = now if now is not None else time.time()
        candidates = self._find(agent_id, capability)
        if not candidates:
            return False, f"no grant exists for '{capability}'", None

        reasons = []
        for g in candidates:
            if g.revoked:
                reasons.append(
                    f"grant {g.grant_id[:14]} revoked by {g.revoked_by}"
                )
                continue
            if g.expires_at is not None and now >= g.expires_at:
                reasons.append(f"grant {g.grant_id[:14]} expired")
                continue
            if (
                g.budget is not None
                and amount is not None
                and g.spent + amount > g.budget
            ):
                reasons.append(
                    f"grant {g.grant_id[:14]} budget exceeded "
                    f"({g.spent + amount:.2f} > {g.budget:.2f})"
                )
                continue
            return True, f"grant {g.grant_id[:14]} valid", g.grant_id

        return False, "; ".join(reasons), None

    def record_spend(self, grant_id: str, amount: float) -> None:
        self._grants[grant_id].spent += amount

    # ---- authorizer protocol (drop-in for allowlist) -------------------

    def is_authorized(self, agent_id: str, capability: str) -> bool:
        ok, _, _ = self.explain(agent_id, capability)
        return ok
