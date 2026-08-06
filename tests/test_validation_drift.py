"""Label-shift vs concept-drift distinction and prior-odds correction."""

import math
import random

import pytest

from agent_dna.validation import assess_drift, ks_statistic, prior_odds_correction


def _window(rng, n, prevalence, pos_loc=0.7, neg_loc=0.3):
    labels = [int(rng.random() < prevalence) for _ in range(n)]
    scores = [
        min(1.0, max(0.0, (pos_loc if y else neg_loc) + rng.gauss(0, 0.08)))
        for y in labels
    ]
    return scores, labels


def test_pure_label_shift_detected_without_concept_drift():
    rng = random.Random(1)
    ref = _window(rng, 400, 0.10)
    cur = _window(rng, 400, 0.35)
    d = assess_drift(*ref, *cur)
    assert d.verdict == "label_shift_only"
    assert d.label_shift_detected and not d.concept_drift_detected
    assert "prior_odds_correction" in d.recommendation
    assert "Retraining is unnecessary" in d.recommendation


def test_concept_drift_detected_when_conditional_distribution_moves():
    rng = random.Random(2)
    ref = _window(rng, 400, 0.2, pos_loc=0.8, neg_loc=0.2)
    cur = _window(rng, 400, 0.2, pos_loc=0.45, neg_loc=0.4)
    d = assess_drift(*ref, *cur)
    assert d.verdict == "concept_drift"
    assert d.concept_drift_detected


def test_no_drift_when_windows_match():
    rng = random.Random(3)
    ref = _window(rng, 400, 0.2)
    cur = _window(rng, 400, 0.2)
    d = assess_drift(*ref, *cur)
    assert d.verdict == "no_drift"


def test_insufficient_data_never_guesses():
    d = assess_drift([0.9] * 5, [1] * 5, [0.1] * 5, [0] * 5)
    assert d.verdict == "insufficient_data"
    assert not d.label_shift_detected and not d.concept_drift_detected


def test_ks_statistic_identical_samples_zero():
    assert ks_statistic([0.1, 0.5, 0.9], [0.1, 0.5, 0.9]) == 0.0


def test_prior_correction_identity_when_prior_unchanged():
    for p in (0.01, 0.3, 0.5, 0.99):
        assert math.isclose(prior_odds_correction(p, 0.2, 0.2), p, abs_tol=1e-12)


def test_prior_correction_direction_and_range():
    p = prior_odds_correction(0.5, 0.1, 0.4)
    assert p > 0.5 and 0 < p < 1
    assert prior_odds_correction(0.5, 0.4, 0.1) < 0.5


def test_prior_correction_rejects_degenerate_priors():
    with pytest.raises(ValueError):
        prior_odds_correction(0.5, 0.0, 0.2)
    with pytest.raises(ValueError):
        prior_odds_correction(0.5, 0.2, 1.0)
