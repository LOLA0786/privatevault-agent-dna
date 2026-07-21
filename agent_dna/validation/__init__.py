"""Model validation for the advisory drift layer (pv-validation/1).

Scope boundary, stated once and enforced everywhere: this package
evaluates and constrains the ADVISORY signal only. Deterministic
precedence levels are unaffected by anything produced here; the only
runtime touch-point is a tighten-only adjustment at the existing
'drift' level via ValidationGuard.
"""

from .drift import (
    DriftAssessment,
    assess_drift,
    ks_statistic,
    prior_odds_correction,
)
from .guard import ValidationGuard
from .metrics import (
    AUCDecomposition,
    SegmentReliability,
    auc,
    auc_decomposition,
    brier_score,
    cross_segments,
    expected_calibration_error,
    log_loss,
    segment_reliability,
    wilson_interval,
)
from .report import (
    FORMAT,
    LabelSourceError,
    ScoreTypeError,
    build_report,
    calibration_metrics_for,
    canonical_json,
    seal,
)

__all__ = [
    "FORMAT", "AUCDecomposition", "DriftAssessment", "LabelSourceError",
    "ScoreTypeError", "SegmentReliability", "ValidationGuard",
    "assess_drift", "auc", "auc_decomposition", "brier_score",
    "build_report", "calibration_metrics_for", "canonical_json",
    "cross_segments", "expected_calibration_error", "ks_statistic",
    "log_loss", "prior_odds_correction", "seal", "segment_reliability",
    "wilson_interval",
]
