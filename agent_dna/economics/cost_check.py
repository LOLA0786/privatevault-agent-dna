"""
CostAnomalyChecker — pre-execution economic sanity check.

Two independent signals, both deterministic math, both evidence-gated:

  1. Cost-ratio anomaly: claimed/estimated cost vs. this agent's
     historical average cost for the capability. Adapted from
     EconTrustEngine's cost_penalty logic (source: PrivateVault.ai
     pv_economics/engines/trust_engine.py).
  2. ROI floor: if a business_value estimate is supplied, claimed
     cost must not exceed it. Adapted from ROIEngine's ratio
     computation (source: pv_economics/engines/roi_engine.py).

Never BLOCKs. Cost anomaly is an efficiency signal, not a security
violation — ceiling is REQUIRE_APPROVAL, same as authorization/drift.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class CostCheckResult:
    flagged: bool
    reasons: List[str] = field(default_factory=list)
    checks_run: List[str] = field(default_factory=list)
    checks_skipped: List[str] = field(default_factory=list)


class CostAnomalyChecker:
    # Ratio above which claimed cost vs. historical average is
    # considered anomalous. Placeholder default — real threshold
    # should be calibrated per deployment, same honesty rule as
    # behavioral drift thresholds.
    COST_RATIO_THRESHOLD = 5.0

    def check(
        self,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> CostCheckResult:
        evidence = (evidence or {}).get("economics")
        run: List[str] = []
        skipped: List[str] = []
        reasons: List[str] = []

        if evidence is None:
            return CostCheckResult(
                flagged=False,
                checks_skipped=["cost_ratio_anomaly", "roi_floor"],
            )

        estimated_cost = evidence.get("estimated_cost_usd")
        historical_avg = evidence.get("historical_avg_cost_usd")
        business_value = evidence.get("business_value_usd")

        # --- signal 1: cost-ratio anomaly ---
        if estimated_cost is not None and historical_avg is not None:
            run.append("cost_ratio_anomaly")
            if historical_avg > 0:
                ratio = estimated_cost / historical_avg
                if ratio > self.COST_RATIO_THRESHOLD:
                    reasons.append(
                        f"cost_ratio_anomaly: estimated ${estimated_cost:.4f} "
                        f"is {ratio:.1f}x historical average "
                        f"${historical_avg:.4f} (threshold "
                        f"{self.COST_RATIO_THRESHOLD}x)"
                    )
        else:
            skipped.append("cost_ratio_anomaly")

        # --- signal 2: ROI floor ---
        if estimated_cost is not None and business_value is not None:
            run.append("roi_floor")
            if business_value <= 0:
                reasons.append(
                    "roi_floor: no business value estimate for a "
                    f"${estimated_cost:.4f} claimed cost"
                )
            elif estimated_cost > business_value:
                reasons.append(
                    f"roi_floor: claimed cost ${estimated_cost:.4f} exceeds "
                    f"estimated business value ${business_value:.4f}"
                )
        else:
            skipped.append("roi_floor")

        return CostCheckResult(
            flagged=bool(reasons),
            reasons=reasons,
            checks_run=run,
            checks_skipped=skipped,
        )
