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

import threading
import time
import uuid
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any

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
        # explain() checks the budget before the rest of the decision
        # runs; record_spend() re-checks under this lock so concurrent
        # ALLOWs cannot jointly overspend (check-then-act race).
        self._spend_lock = threading.Lock()
        # Optional durable ledger (agent_dna.grant_spend). When attached,
        # spend survives restarts and is shared by every worker on the DB.
        self.spend_ledger: Any = None

    def attach_spend_ledger(self, ledger: Any) -> None:
        self.spend_ledger = ledger

    def _spent(self, g: CapabilityGrant) -> Decimal:
        if self.spend_ledger is not None:
            return Decimal(self.spend_ledger.spent(g.grant_id))
        return coerce_amount(g.spent)

    # ---- lifecycle -----------------------------------------------------

    def grant(
        self,
        *,
        agent_id: str,
        capability: str,
        granted_by: str,
        expires_at: float | None = None,
        budget: float | None = None,
        grant_id: str | None = None,
    ) -> CapabilityGrant:
        if grant_id is not None and grant_id in self._grants:
            raise ValueError(f"duplicate grant_id {grant_id!r}")
        g = CapabilityGrant(
            grant_id=grant_id or f"grant-{uuid.uuid4()}",
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
                spent = self._spent(g)
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
        """Atomically commit spend. Raises (fail closed -> BLOCK in the
        guarded engine) if the grant was revoked or the spend would
        exceed the budget since explain() looked at it."""
        delta = coerce_amount(amount)
        with self._spend_lock:
            g = self._grants[grant_id]
            if g.revoked:
                raise ValueError(f"grant {grant_id[:14]} revoked before spend")
            if self.spend_ledger is not None:
                g.spent = self.spend_ledger.commit_spend(grant_id, delta, g.budget)
                return
            current = coerce_amount(g.spent)
            if g.budget is not None:
                budget = coerce_amount(g.budget)
                if current + delta > budget:
                    raise ValueError(
                        f"grant {grant_id[:14]} budget exceeded at commit "
                        f"({current + delta} > {budget})"
                    )
            g.spent = current + delta

    # ---- authorizer protocol (drop-in for allowlist) -------------------

    def is_authorized(self, agent_id: str, capability: str) -> bool:
        ok, _, _ = self.explain(agent_id, capability)
        return ok
