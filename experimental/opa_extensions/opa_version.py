"""
OPA Policy Version Tracking — Audit & Cache Invalidation.

Tracks OPA policy bundle version/hash for every evaluation.
Ensures audit artifacts reference the exact policy version
that produced each decision.
Compatible with docs/compliance/soc2/control_mapping.md.
"""

import hashlib


class OPAVersionTracker:
    """
    Tracks policy bundle versions evaluated by adapter.
    Produces audit artifacts linking decision hash + policy version.
    """

    def __init__(self):
        self.current_version: str | None = None
        self.version_history: list = []
        self.evaluations: dict[str, str] = {}  # decision_ref -> policy_version

    def load_version(self, bundle_path: str | None = None) -> str:
        """
        Derive version hash from bundle content or endpoint metadata.
        Returns SHA256 hash of policy bundle.
        """
        if bundle_path:
            content = open(bundle_path, "rb").read()
        else:
            # In production: fetch /v1/policies and hash response
            content = b"current_policy_bundle"
        version = hashlib.sha256(content).hexdigest()[:32]
        self.current_version = version
        self.version_history.append(version)
        return version

    def record_evaluation(
        self, decision_ref: str, policy_version: str | None = None
    ) -> dict:
        version = policy_version or self.current_version or "unknown"
        self.evaluations[decision_ref] = version
        return {
            "decision_ref": decision_ref,
            "policy_version": version,
            "audit_link": f"pv_decision_version_link_{version}",
        }

    def invalidate_cache_on_version_change(self, adapter) -> bool:
        """
        If policy version changed, adapter should invalidate memory cache.
        """
        new_version = self.load_version(
            adapter.bundle_path if adapter.bundle_path else None
        )
        if (
            adapter._cache
            and len(self.version_history) > 1
            and new_version != self.version_history[-2]
        ):
            adapter._cache.clear()
            adapter._cache_hits = 0
            return True
        return False
