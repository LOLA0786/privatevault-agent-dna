"""Every bullet of the validation-module claim list traces here or to
its sibling test files. Metrics: Wilson, AUC + exact decomposition,
calibration, safeguards."""

import math
import random

import pytest

from agent_dna.validation import (
    auc,
    auc_decomposition,
    brier_score,
    cross_segments,
    expected_calibration_error,
    log_loss,
    segment_reliability,
    wilson_interval,
)


def test_wilson_known_value():
    lo, hi = wilson_interval(8, 10)
    assert abs(lo - 0.4902) < 5e-3
    assert abs(hi - 0.9433) < 5e-3


def test_wilson_boundaries_stay_in_unit_interval():
    lo, hi = wilson_interval(0, 5)
    assert lo == 0.0 and 0 < hi < 1
    lo, hi = wilson_interval(5, 5)
    assert hi == 1.0 and 0 < lo < 1


def test_wilson_rejects_bad_input():
    with pytest.raises(ValueError):
        wilson_interval(1, 0)
    with pytest.raises(ValueError):
        wilson_interval(6, 5)


def test_auc_hand_computed():
    assert auc([0.9, 0.8, 0.7, 0.1], [1, 1, 0, 0]) == 1.0
    assert auc([0.9, 0.6, 0.7, 0.1], [1, 1, 0, 0]) == 0.75


def test_auc_ties_count_half():
    assert auc([0.5, 0.5], [1, 0]) == 0.5


def test_auc_single_class_is_none():
    assert auc([0.1, 0.2], [1, 1]) is None
    assert auc([0.1, 0.2], [0, 0]) is None


def test_decomposition_identity_exact_on_random_data():
    rng = random.Random(42)
    scores = [rng.random() for _ in range(400)]
    labels = [int(rng.random() < 0.3) for _ in range(400)]
    segs = [rng.choice(["a", "b", "c", "d"]) for _ in range(400)]
    d = auc_decomposition(scores, labels, segs)
    assert math.isclose(
        d.auc_global,
        d.within_contribution + d.between_contribution,
        rel_tol=0,
        abs_tol=1e-12,
    )
    assert math.isclose(d.within_pair_share + d.between_pair_share, 1.0, abs_tol=1e-12)
    assert math.isclose(d.auc_global, auc(scores, labels), abs_tol=1e-12)


def test_decomposition_all_one_segment_is_all_within():
    d = auc_decomposition([0.9, 0.1], [1, 0], ["s", "s"])
    assert d.within_pair_share == 1.0
    assert d.between_contribution == 0.0


def test_brier_perfect_and_worst():
    assert brier_score([1.0, 0.0], [1, 0]) == 0.0
    assert brier_score([0.0, 1.0], [1, 0]) == 1.0


def test_log_loss_matches_hand_value():
    assert math.isclose(log_loss([0.8], [1]), -math.log(0.8), abs_tol=1e-12)


def test_ece_perfectly_calibrated_bins_near_zero():
    probs = [0.25] * 4 + [0.75] * 4
    labels = [1, 0, 0, 0, 1, 1, 1, 0]
    assert expected_calibration_error(probs, labels, n_bins=4) == 0.0


def test_calibration_rejects_out_of_range():
    with pytest.raises(ValueError):
        brier_score([1.2], [1])
    with pytest.raises(ValueError):
        log_loss([0.5], [2])


def test_segment_reliability_by_agent_capability_and_cross():
    n = 80
    rng = random.Random(7)
    agents = ["a1" if i < 40 else "a2" for i in range(n)]
    caps = ["pay" if i % 2 else "read" for i in range(n)]
    labels = [int(rng.random() < 0.4) for _ in range(n)]
    scores = [0.6 * y + 0.4 * rng.random() for y in labels]
    for segs in (agents, caps, cross_segments(agents, caps)):
        rows = segment_reliability(scores, labels, segs, min_samples=10)
        assert sum(r.n for r in rows) == n
        for r in rows:
            if r.status == "ok":
                assert r.auc is not None and r.prevalence_ci is not None


def test_min_sample_safeguard_withholds_metrics():
    rows = segment_reliability([0.9, 0.1], [1, 0], ["tiny", "tiny"], min_samples=30)
    assert rows[0].status == "insufficient_samples"
    assert rows[0].auc is None and rows[0].prevalence is None


def test_single_class_safeguard():
    scores = [0.5] * 30
    labels = [1] * 30
    rows = segment_reliability(scores, labels, ["s"] * 30, min_samples=30)
    assert rows[0].status == "single_class"
    assert rows[0].auc is None
    assert rows[0].prevalence == 1.0
