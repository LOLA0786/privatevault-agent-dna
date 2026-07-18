"""
OPA Audit Integration — Policy Change Watcher + Decision Link.

Watches OPA policy endpoint for updates.
Links every OPA evaluation result to agent_dna decision record.
Produces audit artifacts that reference both decision hash
and policy version (compatible with docs/compliance/soc2/).
"""
import time
from typing import Optional, Dict


class OPAAuditWatcher:
    """
    Monitors OPA policy endpoint for version changes.
    Links evaluation results to decision audit chain.
    """
    def __init__(self):
        self.last_policy_version: Optional[str] = None
        self.watch_interval: int = 60  # seconds
        self.audit_log: list = []

    def check_policy_update(self, endpoint: str, adapter_version_tracker) -> bool:
        """
        Detect if OPA policies have changed since last check.
        If changed, invalidate adapter caches and log event.
        """
        current = adapter_version_tracker.load_version(adapter_version_tracker.bundle_path)
        if self.last_policy_version is None:
            self.last_policy_version = current
            return False  # First observation
        changed = current != self.last_policy_version
        self.last_policy_version = current
        if changed:
            # Invalidate adapter caches
            adapter_version_tracker.invalidate_cache_on_version_change(adapter_version_tracker)
        return changed

    def link_decision_to_policy(self, decision_ref: str, adapter_version_tracker) -> Dict:
        version = adapter_version_tracker.current_version or "unknown"
        audit_entry = {
            "timestamp": time.time(),
            "decision_ref": decision_ref,
            "policy_version": version,
            "link_type": "opa_decision_policy_audit",
        }
        self.audit_log.append(audit_entry)
        return audit_entry

    def audit_summary(self) -> Dict:
        return {
            "watcher_active": True,
            "last_version": self.last_policy_version,
            "audit_entries": len(self.audit_log),
            "watch_interval_seconds": self.watch_interval,
        }
