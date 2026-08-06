"""
Behavioral Profile Diff Engine.

Structural similarity and operational risk are intentionally separated.

Similarity answers:

    "How different are these agents?"

Risk answers:

    "How much of that difference is NOT explained by approved evolution?"
"""

from __future__ import annotations

from dataclasses import dataclass

from .authorization import AuthorizationPolicy
from .fingerprint import AgentFingerprint
from .similarity import SimilarityEngine


@dataclass
class DiffReport:
    # identity

    overall_similarity: float

    # Legacy compatibility
    added_capabilities: list[str]

    # change accounting

    authorized_capabilities: list[str]

    unexpected_capabilities: list[str]

    removed_capabilities: list[str]

    # operational

    risk: str

    summary: str

    @property
    def authorized_additions(self) -> list[str]:
        return self.authorized_capabilities

    @property
    def unexpected_additions(self) -> list[str]:
        return self.unexpected_capabilities

    @property
    def unauthorized_additions(self) -> list[str]:
        return self.unexpected_capabilities

    @property
    def added_transitions(self) -> list[str]:
        return []

    @property
    def removed_transitions(self) -> list[str]:
        return []


class ProfileDiffEngine:
    def __init__(
        self,
        policy: AuthorizationPolicy | None = None,
    ):

        self.policy = policy or AuthorizationPolicy()

        self.similarity = SimilarityEngine()

    def diff(
        self,
        trusted: AgentFingerprint,
        candidate: AgentFingerprint,
        policy: AuthorizationPolicy | None = None,
    ) -> DiffReport:

        policy = policy or self.policy

        sim = self.similarity.compare(
            trusted,
            candidate,
        )

        trusted_caps = set(trusted.capability_counts)

        candidate_caps = set(candidate.capability_counts)

        added = sorted(candidate_caps - trusted_caps)

        removed = sorted(trusted_caps - candidate_caps)

        authorized = []
        unexpected = []

        for capability in added:
            if policy.is_authorized(
                trusted.agent_id,
                capability,
            ):
                authorized.append(
                    capability,
                )

            else:
                unexpected.append(
                    capability,
                )

        #
        # Risk depends ONLY on unexplained change.
        #

        if unexpected:
            if len(unexpected) >= 2:
                risk = "HIGH"

            else:
                risk = "MEDIUM"

            summary = "Behavior contains unexpected capability evolution."

        else:
            risk = "LOW"

            if authorized:
                summary = "Behavior evolved through approved capability grants."

            else:
                summary = "No meaningful behavioral evolution detected."

        return DiffReport(
            overall_similarity=sim.overall_similarity,
            # Legacy API
            added_capabilities=authorized + unexpected,
            removed_capabilities=removed,
            # New API
            authorized_capabilities=authorized,
            unexpected_capabilities=unexpected,
            risk=risk,
            summary=summary,
        )
