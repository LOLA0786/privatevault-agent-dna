"""pv-validation/1 -- hash-sealed model validation reports.

The same trust model as DRP decision records: the report body is
canonical JSON (sorted keys, compact separators) sealed with SHA-256.
``tools/verify_validation.py`` recomputes the seal and re-checks the
internal identities with the standard library alone -- an auditor
never has to trust this package to check its numbers.

Honesty enforcement lives HERE, at construction time:

- ``score_type`` must be declared: "ranking" or "probability".
- Calibration metrics (Brier, log loss, ECE) are computed ONLY for
  declared probability scores. Requesting them for a ranking score
  raises ScoreTypeError -- it is not a warning, because a calibration
  number attached to a ranking score is exactly the kind of
  plausible-looking nonsense a review should never contain.
- ``label_source`` must be declared "independent" with a note naming
  it. Self-labelled outcomes (the agent grading its own homework)
  are refused.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from .drift import DriftAssessment, assess_drift
from .metrics import (
    DEFAULT_MIN_SAMPLES,
    auc_decomposition,
    brier_score,
    cross_segments,
    expected_calibration_error,
    log_loss,
    segment_reliability,
)

FORMAT = "pv-validation/1"
DEFAULT_TTL_SECONDS = 90 * 24 * 3600  # reports go stale; 90 days default


class ScoreTypeError(ValueError):
    """Calibration metrics requested for a non-probability score."""


class LabelSourceError(ValueError):
    """Ground-truth labels are not independently sourced."""


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def seal(body: dict[str, Any]) -> dict[str, Any]:
    h = hashlib.sha256(canonical_json(body).encode()).hexdigest()
    return {"body": body, "report_hash": h}


def build_report(
    *,
    score_name: str,
    score_type: str,
    scores: list[float],
    labels: list[int],
    agents: list[str],
    capabilities: list[str],
    label_source: str,
    label_source_note: str,
    reference: tuple[list[float], list[int]] | None = None,
    min_samples: int = DEFAULT_MIN_SAMPLES,
    ece_bins: int = 10,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    now: float | None = None,
) -> dict[str, Any]:
    """Build and seal a pv-validation/1 report envelope.

    ``reference`` (optional): validation-time (scores, labels) window
    for drift assessment against the current window.
    """
    if score_type not in ("ranking", "probability"):
        raise ScoreTypeError(
            f"score_type must be 'ranking' or 'probability', got {score_type!r}"
        )
    if label_source != "independent":
        raise LabelSourceError(
            "labels must be independently sourced (label_source='independent'); "
            "outcomes labelled by the scored system itself are refused"
        )
    if not label_source_note.strip():
        raise LabelSourceError("label_source_note must name the label source")
    n = len(scores)
    if not (n == len(labels) == len(agents) == len(capabilities)):
        raise ValueError("scores/labels/agents/capabilities length mismatch")
    if n == 0:
        raise ValueError("empty dataset")

    ts = time.time() if now is None else now
    n_pos = sum(labels)

    # global + exact decomposition (agent segments)
    deco = auc_decomposition(scores, labels, agents)

    body: dict[str, Any] = {
        "format": FORMAT,
        "created_at": ts,
        "expires_at": ts + ttl_seconds,
        "score": {"name": score_name, "type": score_type},
        "dataset": {
            "n": n,
            "n_pos": n_pos,
            "n_neg": n - n_pos,
            "label_source": label_source,
            "label_source_note": label_source_note,
        },
        "safeguards": {
            "min_samples": min_samples,
            "requires_both_classes": True,
        },
        "global": None,
        "segments": {
            "by_agent": _seg(scores, labels, agents, min_samples),
            "by_capability": _seg(scores, labels, capabilities, min_samples),
            "by_agent_capability": _seg(
                scores, labels, cross_segments(agents, capabilities), min_samples
            ),
        },
        "calibration": None,
        "drift": None,
        "limitations": [
            "Metrics describe the evaluated dataset only; they are not a "
            "guarantee on future traffic.",
            "ECE depends on the fixed equal-width binning recorded in "
            "this report (n_bins); it is not comparable across binnings.",
            "Segment metrics below min_samples are withheld by design.",
            "This report validates the ADVISORY drift signal only. "
            "Deterministic levels L0-L4 are outside its scope and are "
            "unaffected by its contents.",
        ],
    }

    if deco is not None:
        body["global"] = {
            "auc": deco.auc_global,
            "auc_within_contribution": deco.within_contribution,
            "auc_between_contribution": deco.between_contribution,
            "within_pair_share": deco.within_pair_share,
            "between_pair_share": deco.between_pair_share,
            "n_pairs": deco.n_pairs,
            "segmentation": "agent",
        }

    if score_type == "probability":
        body["calibration"] = {
            "brier": brier_score(scores, labels),
            "log_loss": log_loss(scores, labels),
            "ece": expected_calibration_error(scores, labels, ece_bins),
            "n_bins": ece_bins,
        }

    if reference is not None:
        ref_scores, ref_labels = reference
        body["drift"] = _drift_dict(
            assess_drift(
                ref_scores, ref_labels, scores, labels, min_samples=min_samples
            )
        )

    return seal(body)


def calibration_metrics_for(
    score_type: str, probs: list[float], labels: list[int]
) -> dict[str, float]:
    """Explicit gate: refuse calibration math for ranking scores."""
    if score_type != "probability":
        raise ScoreTypeError(
            "Brier/log-loss/ECE are defined for calibrated probabilities; "
            f"score_type={score_type!r} is a ranking score. Refusing to emit "
            "calibration numbers that would be quoted as if meaningful."
        )
    return {
        "brier": brier_score(probs, labels),
        "log_loss": log_loss(probs, labels),
        "ece": expected_calibration_error(probs, labels),
    }


def _seg(scores, labels, segments, min_samples):
    return [
        {
            "key": r.key,
            "n": r.n,
            "n_pos": r.n_pos,
            "prevalence": r.prevalence,
            "prevalence_ci": list(r.prevalence_ci) if r.prevalence_ci else None,
            "auc": r.auc,
            "status": r.status,
        }
        for r in segment_reliability(scores, labels, segments, min_samples)
    ]


def _drift_dict(d: DriftAssessment) -> dict[str, Any]:
    return {
        "label_shift_detected": d.label_shift_detected,
        "concept_drift_detected": d.concept_drift_detected,
        "prevalence_reference": d.prevalence_reference,
        "prevalence_current": d.prevalence_current,
        "prevalence_reference_ci": list(d.prevalence_reference_ci),
        "prevalence_current_ci": list(d.prevalence_current_ci),
        "ks_pos": d.ks_pos,
        "ks_neg": d.ks_neg,
        "auc_reference": d.auc_reference,
        "auc_current": d.auc_current,
        "verdict": d.verdict,
        "recommendation": d.recommendation,
    }
