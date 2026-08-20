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
from decimal import Decimal

from agent_dna.amount import INVALID_AMOUNT, InvalidAmountError, coerce_amount


@dataclass
class CapabilityGrant:
    grant_id: str
    agent_id: str
    capability: str
    granted_by: str
    expires_at: float | None = None  # epoch seconds; None = no expiry
    budget: float | None = None  # cumulative amount ceiling; None = unmetered
    spent: Decimal = field(default_factory=lambda: Decimal("0"))
    revoked: bool = False
    revoked_at: float | None = None
    revoked_by: str | None = None
    created_at: float = field(default_factory=time.time)


class GrantRegistry:
    """In-memory grant store + authorizer. Same is_authorized contract
    as the allowlist authorizer (drop-in), plus an explain() that names
    the failing condition and the grant involved."""

    # Overwritten to "grants_file" when loaded from PV_GRANTS_FILE.
    authorization_mode: str = "deny_all"

    def __init__(self) -> None:
        self._grants: dict[str, CapabilityGrant] = {}
        self.authorization_mode = "deny_all"

    # ---- lifecycle -----------------------------------------------------

    def grant(
        self,
        *,
        agent_id: str,
        capability: str,
        granted_by: str,
        expires_at: float | None = None,
        budget: float | None = None,
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
        if self.authorization_mode == "deny_all" and self._grants:
            # Populated registries used in tests/demos are grant-backed,
            # not the production empty deny-all default.
            self.authorization_mode = "grants"
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
            g
            for g in self._grants.values()
            if g.agent_id == agent_id and g.capability == capability
        ]

    def explain(  # noqa: C901 — ordered grant lifecycle checklist
        self,
        agent_id: str,
        capability: str,
        amount: object | None = None,
        now: float | None = None,
    ) -> tuple[bool, str, str | None]:
        """(authorized, reason, grant_id). Reason names the specific
        failing condition — 'grant expired', 'grant revoked', 'budget
        exceeded' — never just 'no'."""
        now = now if now is not None else time.time()
        candidates = self._find(agent_id, capability)
        if not candidates:
            return False, f"no grant exists for '{capability}'", None

        coerced_amount = None
        invalid_amount_reason: str | None = None
        if amount is not None:
            try:
                coerced_amount = coerce_amount(amount)
            except InvalidAmountError as exc:
                return False, str(exc), None
        reasons = []
        for g in candidates:
            if g.revoked:
                reasons.append(f"grant {g.grant_id[:14]} revoked by {g.revoked_by}")
                continue
            if g.expires_at is not None and now >= g.expires_at:
                reasons.append(f"grant {g.grant_id[:14]} expired")
                continue
            if g.budget is not None:
                if coerced_amount is None:
                    invalid_amount_reason = (
                        f"{INVALID_AMOUNT}: amount required for budgeted grant"
                    )
                    reasons.append(invalid_amount_reason)
                    continue
                spent = coerce_amount(g.spent)
                budget = coerce_amount(g.budget)
                projected = spent + coerced_amount
                if projected > budget:
                    reasons.append(
                        f"grant {g.grant_id[:14]} budget exceeded "
                        f"({projected} > {budget})"
                    )
                    continue
            return True, f"grant {g.grant_id[:14]} valid", g.grant_id

        if invalid_amount_reason is not None and all(
            INVALID_AMOUNT in item for item in reasons
        ):
            return False, invalid_amount_reason, None
        return False, "; ".join(reasons), None

    def record_spend(self, grant_id: str, amount: object) -> None:
        delta = coerce_amount(amount)
        current = coerce_amount(self._grants[grant_id].spent)
        self._grants[grant_id].spent = current + delta

    # ---- authorizer protocol (drop-in for allowlist) -------------------

    def is_authorized(self, agent_id: str, capability: str) -> bool:
        ok, _, _ = self.explain(agent_id, capability)
        return ok
