"""
Pre-execution economics check. Vendored/adapted from PrivateVault.ai's
pv_economics/engines/roi_engine.py and trust_engine.py cost-anomaly
logic — NOT waste_engine.py or success_engine.py, which require
post-execution telemetry (actual tokens used, actual retries) that
does not exist at decide()-time. Those belong on outcome reporting,
not enforcement, and are not wired in here.

Evidence-honest, same discipline as UAALConstraintChecker: absent
evidence means the check is SKIPPED, never silently passed.
"""

from .cost_check import CostAnomalyChecker, CostCheckResult

__all__ = ["CostAnomalyChecker", "CostCheckResult"]
