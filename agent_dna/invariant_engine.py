"""
Behavioral Invariant Runtime Validator.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from .invariants import BehavioralInvariant


@dataclass
class InvariantViolation:

    violated: bool
    message: str


class InvariantEngine:

    def __init__(
        self,
        invariants: Dict[str, BehavioralInvariant],
    ):
        self.invariants = invariants

    def validate(
        self,
        capability: str,
        previous: Optional[str],
    ) -> InvariantViolation:

        previous = previous or "__START__"

        invariant = self.invariants.get(capability)

        if invariant is None:
            return InvariantViolation(
                False,
                "",
            )

        if previous not in invariant.allowed_predecessors:

            return InvariantViolation(
                True,
                (
                    f"Behavioral invariant violated. "
                    f"'{capability}' "
                    f"cannot follow "
                    f"'{previous}'."
                ),
            )

        return InvariantViolation(
            False,
            "",
        )
