"""
Behavioral Profile Diff Engine.

Supports authorized behavioral evolution.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .authorization import AuthorizationPolicy, CapabilityGrant
from .fingerprint import AgentFingerprint
from .similarity import SimilarityEngine


@dataclass
class AuthorizedCapability:
    capability: str
    approved_by: str
    ticket: str


@dataclass
class DiffReport:
    overall_similarity: float

    risk: str

    authorized_additions: List[AuthorizedCapability]
    unauthorized_additions: List[str]

    removed_capabilities: List[str]

    added_transitions: List[str]
    removed_transitions: List[str]

    summary: str


class ProfileDiffEngine:

    def diff(
        self,
        trusted: AgentFingerprint,
        candidate: AgentFingerprint,
        policy: Optional[AuthorizationPolicy] = None,
    ) -> DiffReport:

        similarity = SimilarityEngine().compare(
            trusted,
            candidate,
        )

        trusted_caps = set(trusted.capability_counts)
        candidate_caps = set(candidate.capability_counts)

        added = sorted(candidate_caps - trusted_caps)
        removed = sorted(trusted_caps - candidate_caps)

        authorized: List[AuthorizedCapability] = []
        unauthorized: List[str] = []

        for capability in added:

            grant: CapabilityGrant | None = None

            if policy is not None:
                grant = policy.lookup(
                    candidate.agent_id,
                    capability,
                )

            if grant:

                authorized.append(
                    AuthorizedCapability(
                        capability=grant.capability,
                        approved_by=grant.approved_by,
                        ticket=grant.ticket,
                    )
                )

            else:
                unauthorized.append(capability)

        trusted_trans = set(trusted.transitions)
        candidate_trans = set(candidate.transitions)

        added_transitions = sorted(candidate_trans - trusted_trans)
        removed_transitions = sorted(trusted_trans - candidate_trans)

        #
        # Risk calibration
        #

        if len(unauthorized) == 0:
            risk = "LOW"

        elif len(unauthorized) == 1 and len(authorized) >= 1:
            risk = "MEDIUM"

        else:
            risk = "HIGH"

        if risk == "LOW":
            summary = "Behavior evolution matches approved capability changes."

        elif risk == "MEDIUM":
            summary = (
                "Behavior includes approved evolution and one unexpected capability."
            )

        else:
            summary = (
                "Behavior contains multiple unexpected capability changes."
            )

        return DiffReport(
            overall_similarity=similarity.overall_similarity,
            risk=risk,
            authorized_additions=authorized,
            unauthorized_additions=unauthorized,
            removed_capabilities=removed,
            added_transitions=added_transitions,
            removed_transitions=removed_transitions,
            summary=summary,
        )
