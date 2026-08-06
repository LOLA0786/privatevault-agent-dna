"""Fresh tests for the vendored WeightedQuorum — the source repo had
zero tests for this logic prior to vendoring. Covers the arithmetic,
the threshold boundary, and the adversarial-weight edge cases a real
Byzantine scenario would actually exercise."""

from dataclasses import FrozenInstanceError

import pytest

from agent_dna.consensus import LeaderState, Vote, WeightedQuorum


def test_unanimous_approval():
    q = WeightedQuorum()
    votes = [Vote(weight=1.0, approve=True) for _ in range(5)]
    assert q.evaluate(votes) == 1.0
    assert q.approved(votes)


def test_unanimous_rejection():
    q = WeightedQuorum()
    votes = [Vote(weight=1.0, approve=False) for _ in range(5)]
    assert q.evaluate(votes) == 0.0
    assert not q.approved(votes)


def test_exact_threshold_boundary_approves():
    """67% exactly must approve — threshold is >=, not >."""
    q = WeightedQuorum()
    votes = [Vote(weight=1.0, approve=True) for _ in range(67)] + [
        Vote(weight=1.0, approve=False) for _ in range(33)
    ]
    assert q.evaluate(votes) == pytest.approx(0.67)
    assert q.approved(votes)


def test_just_below_threshold_rejects():
    q = WeightedQuorum()
    votes = [Vote(weight=1.0, approve=True) for _ in range(66)] + [
        Vote(weight=1.0, approve=False) for _ in range(34)
    ]
    assert q.evaluate(votes) < 0.67
    assert not q.approved(votes)


def test_no_votes_does_not_divide_by_zero():
    q = WeightedQuorum()
    assert q.evaluate([]) == 0.0
    assert not q.approved([])


def test_weighted_minority_can_outvote_unweighted_majority():
    """The whole point of WEIGHTED quorum: a small number of
    high-trust voters can outweigh a larger number of low-trust
    voters. This is the property a Byzantine scenario depends on."""
    q = WeightedQuorum()
    votes = [
        Vote(weight=10.0, approve=True),
        Vote(weight=10.0, approve=True),
    ] + [Vote(weight=0.1, approve=False) for _ in range(50)]
    assert q.approved(votes)


def test_all_zero_weight_votes_reject_by_zero_division_guard():
    q = WeightedQuorum()
    votes = [Vote(weight=0.0, approve=True) for _ in range(10)]
    assert q.evaluate(votes) == 0.0
    assert not q.approved(votes)


def test_byzantine_third_cannot_override_honest_two_thirds():
    """The canonical Byzantine claim: up to 1/3 adversarial weight
    voting the WRONG way must not flip a 2/3 honest majority."""
    q = WeightedQuorum()
    honest = [Vote(weight=1.0, approve=True) for _ in range(67)]
    byzantine = [Vote(weight=1.0, approve=False) for _ in range(33)]
    assert q.approved(honest + byzantine)


def test_byzantine_third_can_block_below_two_thirds():
    """Honest claim boundary check: if honest support drops even
    slightly below 2/3, adversarial votes DO block approval. This is
    the failure mode the threshold is supposed to guard, verified as
    a real behavior rather than assumed."""
    q = WeightedQuorum()
    honest = [Vote(weight=1.0, approve=True) for _ in range(66)]
    byzantine = [Vote(weight=1.0, approve=False) for _ in range(34)]
    assert not q.approved(honest + byzantine)


def test_leader_state_is_frozen_and_carries_trust_score():
    ls = LeaderState(cluster_id="c1", healthy=True, trust_score=0.95)
    assert ls.trust_score == 0.95
    with pytest.raises(FrozenInstanceError):
        ls.healthy = False  # frozen dataclass must reject mutation
