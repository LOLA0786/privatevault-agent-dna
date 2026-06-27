"""
Reference implementations of invariant and authorization policies.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterable, Optional, Tuple


# ----------------------------------------------------------------------
# Invariants
# ----------------------------------------------------------------------

@dataclass
class InvariantResult:
    violated: bool
    message: str = ""


class SequenceInvariantEngine:

    def __init__(
        self,
        forbidden_transitions: Iterable[Tuple[str, str]],
    ):
        self.forbidden = set(forbidden_transitions)

    def validate(
        self,
        capability: str,
        previous: Optional[str],
    ) -> InvariantResult:

        if previous is not None and (
            previous,
            capability,
        ) in self.forbidden:

            return InvariantResult(
                True,
                (
                    f"Behavioral invariant violated: "
                    f"'{capability}' cannot follow '{previous}'."
                ),
            )

        return InvariantResult(False, "")


# ----------------------------------------------------------------------
# Authorization
# ----------------------------------------------------------------------

@dataclass
class CapabilityGrant:
    capability: str
    approved_by: str = ""
    ticket: str = ""
    environment: str = "prod"
    expires_at: Optional[float] = None


class GrantAuthorizationPolicy:

    def __init__(
        self,
        baseline_capabilities,
        grants=(),
    ):
        self.baseline = set(baseline_capabilities)
        self.grants = {
            g.capability: g
            for g in grants
        }

    def is_authorized(
        self,
        agent_id: str,
        capability: str,
        now: Optional[float] = None,
    ) -> bool:

        if capability in self.baseline:
            return True

        grant = self.grants.get(capability)

        if grant is None:
            return False

        if (
            grant.expires_at is not None
            and
            (now or time.time()) > grant.expires_at
        ):
            return False

        return True

    def grant_for(
        self,
        capability: str,
    ):
        return self.grants.get(capability)
