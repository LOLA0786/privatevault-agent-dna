"""Development-only open authorizer — operator-configured, never caller-toggled.

Attached only when PV_ALLOW_NO_AUTH opts into unauthenticated development.
The mode is recorded in decision evidence as authorization_mode=open.
"""

from __future__ import annotations


class OpenAuthorizer:
    """Always authorizes. Distinct from authorizer=None (fail-closed)."""

    authorization_mode = "open"

    def is_authorized(self, agent_id: str, capability: str) -> bool:
        return True

    def explain(
        self,
        agent_id: str,
        capability: str,
        amount: float | None = None,
        now: float | None = None,
    ) -> tuple[bool, str, str | None]:
        return (
            True,
            "authorization open (operator development mode: PV_ALLOW_NO_AUTH)",
            None,
        )
