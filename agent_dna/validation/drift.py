"""Label-shift vs concept-drift distinction, and prior-odds correction.

The operational question this module answers: *when the incident rate
in production moves, do we need to retrain the drift scorer, or only
re-weight its output?*

- **Label shift**: P(y) changed, P(score | y) did not. The scorer's
  ranking behavior is intact; a closed-form prior-odds correction of
  probability outputs is sufficient. Retraining is unnecessary churn.
- **Concept drift**: P(score | y) itself changed -- the scorer no
  longer separates outcomes the way it did at validation time.
  No output re-weighting fixes that; investigate/retrain.

Detection here is deliberately conservative and fully reproducible:
- label shift: disjoint Wilson CIs on prevalence (reference vs current)
- concept drift: class-conditional Kolmogorov-Smirnov statistic above
  threshold on either class, or AUC degradation beyond tolerance
Both require minimum sample counts; below them the verdict is
"insufficient_data", never a guess.

Standard library only. Formulas in docs/VALIDATION-MATH.md.
"""

from __future__ import annotations

from dataclasses import dataclass

from .metrics import DEFAULT_MIN_SAMPLES, auc, wilson_interval


def ks_statistic(a: list[float], b: list[float]) -> float:
    """Two-sample Kolmogorov-Smirnov statistic: sup |F_a - F_b|."""
    if not a or not b:
        raise ValueError("ks_statistic requires non-empty samples")
    sa, sb = sorted(a), sorted(b)
    i = j = 0
    d = 0.0
    na, nb = len(sa), len(sb)
    while i < na and j < nb:
        x = sa[i] if sa[i] <= sb[j] else sb[j]
        while i < na and sa[i] <= x:
            i += 1
        while j < nb and sb[j] <= x:
            j += 1
        d = max(d, abs(i / na - j / nb))
    return d


@dataclass(frozen=True)
class DriftAssessment:
    label_shift_detected: bool
    concept_drift_detected: bool
    prevalence_reference: float
    prevalence_current: float
    prevalence_reference_ci: tuple[float, float]
    prevalence_current_ci: tuple[float, float]
    ks_pos: float | None
    ks_neg: float | None
    auc_reference: float | None
    auc_current: float | None
    verdict: str
    # "no_drift" | "label_shift_only" | "concept_drift"
    # | "insufficient_data"
    recommendation: str


def assess_drift(
    ref_scores: list[float],
    ref_labels: list[int],
    cur_scores: list[float],
    cur_labels: list[int],
    *,
    ks_threshold: float = 0.15,
    auc_drop_tolerance: float = 0.05,
    min_samples: int = DEFAULT_MIN_SAMPLES,
) -> DriftAssessment:
    """Compare a current window against the validation-time reference."""
    n_ref, n_cur = len(ref_labels), len(cur_labels)
    if n_ref < min_samples or n_cur < min_samples:
        return _insufficient(ref_labels, cur_labels)

    ref_pos = [s for s, y in zip(ref_scores, ref_labels, strict=True) if y == 1]
    ref_neg = [s for s, y in zip(ref_scores, ref_labels, strict=True) if y == 0]
    cur_pos = [s for s, y in zip(cur_scores, cur_labels, strict=True) if y == 1]
    cur_neg = [s for s, y in zip(cur_scores, cur_labels, strict=True) if y == 0]
    if not (ref_pos and ref_neg and cur_pos and cur_neg):
        return _insufficient(ref_labels, cur_labels)

    p_ref, p_cur = len(ref_pos) / n_ref, len(cur_pos) / n_cur
    ci_ref = wilson_interval(len(ref_pos), n_ref)
    ci_cur = wilson_interval(len(cur_pos), n_cur)
    label_shift = ci_ref[1] < ci_cur[0] or ci_cur[1] < ci_ref[0]

    k_pos = ks_statistic(ref_pos, cur_pos)
    k_neg = ks_statistic(ref_neg, cur_neg)
    a_ref = auc(ref_scores, ref_labels)
    a_cur = auc(cur_scores, cur_labels)
    auc_degraded = (
        a_ref is not None and a_cur is not None
        and (a_ref - a_cur) > auc_drop_tolerance
    )
    concept = k_pos > ks_threshold or k_neg > ks_threshold or auc_degraded

    if concept:
        verdict = "concept_drift"
        rec = ("P(score|y) changed: re-weighting outputs cannot fix this. "
               "Investigate the behavioral change; recalibrate or retrain "
               "the scorer against fresh, independently labelled traces.")
    elif label_shift:
        verdict = "label_shift_only"
        rec = ("Only P(y) moved; ranking behavior is intact. Apply "
               "prior_odds_correction to probability outputs. "
               "Retraining is unnecessary.")
    else:
        verdict = "no_drift"
        rec = "No action required."

    return DriftAssessment(
        label_shift_detected=label_shift,
        concept_drift_detected=concept,
        prevalence_reference=p_ref,
        prevalence_current=p_cur,
        prevalence_reference_ci=ci_ref,
        prevalence_current_ci=ci_cur,
        ks_pos=k_pos,
        ks_neg=k_neg,
        auc_reference=a_ref,
        auc_current=a_cur,
        verdict=verdict,
        recommendation=rec,
    )


def _insufficient(ref_labels: list[int], cur_labels: list[int]) -> DriftAssessment:
    def prev_ci(labels: list[int]) -> tuple[float, tuple[float, float]]:
        n = len(labels)
        k = sum(labels)
        if n == 0:
            return 0.0, (0.0, 1.0)
        return k / n, wilson_interval(k, n)

    p_ref, ci_ref = prev_ci(ref_labels)
    p_cur, ci_cur = prev_ci(cur_labels)
    return DriftAssessment(
        label_shift_detected=False,
        concept_drift_detected=False,
        prevalence_reference=p_ref,
        prevalence_current=p_cur,
        prevalence_reference_ci=ci_ref,
        prevalence_current_ci=ci_cur,
        ks_pos=None, ks_neg=None,
        auc_reference=None, auc_current=None,
        verdict="insufficient_data",
        recommendation=("Below minimum sample count in one or both windows; "
                        "no drift verdict is issued. Collect more labelled "
                        "outcomes before acting."),
    )


def prior_odds_correction(p: float, pi_train: float, pi_deploy: float) -> float:
    """Adjust a calibrated probability for a change in class prior.

        p' = p·r / (p·r + (1-p)·s),  r = pi'/pi,  s = (1-pi')/(1-pi)

    Valid ONLY under label shift (P(score|y) unchanged) and ONLY for
    scores validated as calibrated probabilities. Applying it to a
    ranking score is meaningless; report.py enforces the declaration.
    Identity when pi' == pi (checked by tests).
    """
    for name, v in (("p", p), ("pi_train", pi_train), ("pi_deploy", pi_deploy)):
        if not (0.0 < v < 1.0) if name != "p" else not (0.0 <= v <= 1.0):
            raise ValueError(f"{name} out of range: {v!r}")
    r = pi_deploy / pi_train
    s = (1 - pi_deploy) / (1 - pi_train)
    num = p * r
    return num / (num + (1 - p) * s)
