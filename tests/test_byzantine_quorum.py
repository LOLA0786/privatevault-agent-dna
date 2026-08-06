"""ByzantineQuorum: honest-path parity with the original implementation,
plus one pinned test per security fix (F1-F5) from the 2026-07 rewrite.

The original implementation had latent security bugs found during the
craft rewrite: future-dated votes accepted forever, nonce stored but
never checked (docstring claimed replay protection), duplicate APPROVE
votes from one agent inflating both trust mass and the approve count,
expired votes widening the majority denominator, and a fresh
TrustRegistry per check making configured trust scores unreachable.
Each fix is regression-locked here.
"""

import pytest

from agent_dna.consensus.byzantine import CLOCK_SKEW_SECONDS, ByzantineQuorum
from agent_dna.consensus.secure_quorum import TrustRegistry
from agent_dna.consensus.signing import register_key, sign_message

T0 = 1_750_000_000.0


def _clock_at(t):
    return lambda: t


def _agents(n):
    ids = [f"agent-{i}" for i in range(n)]
    for a in ids:
        register_key(a, f"secret-{a}")
    return ids


def _cast(q, action, agent, vote, message_hash="mh-1", ts=T0, nonce=None):
    linked = (
        f"{q.prev_decision_hash}:{message_hash}"
        if q.prev_decision_hash
        else message_hash
    )
    q.submit_vote(
        action,
        agent,
        vote,
        sign_message(agent, linked),
        message_hash,
        timestamp=ts,
        nonce=nonce,
    )


# ---------------------------------------------------- honest-path parity


def test_four_honest_approvals_reach_quorum():
    q = ByzantineQuorum(clock=_clock_at(T0))
    for a in _agents(4):
        _cast(q, "act", a, "APPROVE")
    assert q.check_quorum("act") is True


def test_below_min_nodes_never_approves():
    q = ByzantineQuorum(min_nodes=4, clock=_clock_at(T0))
    for a in _agents(3):
        _cast(q, "act", a, "APPROVE")
    assert q.check_quorum("act") is False


def test_reject_majority_blocks():
    q = ByzantineQuorum(clock=_clock_at(T0))
    ids = _agents(5)
    for a in ids[:2]:
        _cast(q, "act", a, "APPROVE")
    for a in ids[2:]:
        _cast(q, "act", a, "REJECT")
    assert q.check_quorum("act") is False


def test_forged_signature_does_not_count():
    q = ByzantineQuorum(clock=_clock_at(T0))
    ids = _agents(4)
    for a in ids[:3]:
        _cast(q, "act", a, "APPROVE")
    q.submit_vote("act", ids[3], "APPROVE", "deadbeef" * 8, "mh-1", timestamp=T0)
    assert q.check_quorum("act") is False


def test_prev_hash_links_subsequent_votes_and_unlinked_sigs_fail():
    q = ByzantineQuorum(min_nodes=2, threshold=0.6, clock=_clock_at(T0))
    ids = _agents(2)
    q.set_prev_hash("h" * 8)
    q.submit_vote(
        "act", ids[0], "APPROVE", sign_message(ids[0], "mh-1"), "mh-1", timestamp=T0
    )
    _cast(q, "act", ids[1], "APPROVE")
    assert q.check_quorum("act") is False
    _cast(q, "act", ids[0], "APPROVE")
    assert q.check_quorum("act") is True


def test_votes_property_keeps_legacy_shape():
    q = ByzantineQuorum(clock=_clock_at(T0))
    (a,) = _agents(1)
    _cast(q, "act", a, "APPROVE", nonce="n-1")
    rows = q.votes["act"]
    assert set(rows[0]) == {"agent", "vote", "signature", "hash", "timestamp", "nonce"}


def test_expired_vote_rejected_at_submission():
    q = ByzantineQuorum(expiry=30, clock=_clock_at(T0))
    (a,) = _agents(1)
    with pytest.raises(ValueError, match="expired"):
        _cast(q, "act", a, "APPROVE", ts=T0 - 31)


# ------------------------------------------------------- F1: future votes


def test_f1_future_dated_vote_rejected():
    q = ByzantineQuorum(clock=_clock_at(T0))
    (a,) = _agents(1)
    with pytest.raises(ValueError, match="future"):
        _cast(q, "act", a, "APPROVE", ts=T0 + CLOCK_SKEW_SECONDS + 1)


def test_f1_small_clock_skew_tolerated():
    q = ByzantineQuorum(min_nodes=1, threshold=0.4, clock=_clock_at(T0))
    (a,) = _agents(1)
    _cast(q, "act", a, "APPROVE", ts=T0 + 5)
    assert q.check_quorum("act") is True


# ---------------------------------------------------------- F2: replay


def test_f2_replayed_nonce_rejected():
    q = ByzantineQuorum(clock=_clock_at(T0))
    (a,) = _agents(1)
    _cast(q, "act", a, "APPROVE", nonce="n-1")
    with pytest.raises(ValueError, match="replayed"):
        _cast(q, "act", a, "APPROVE", nonce="n-1")


def test_f2_same_nonce_ok_across_actions():
    q = ByzantineQuorum(clock=_clock_at(T0))
    (a,) = _agents(1)
    _cast(q, "a1", a, "APPROVE", nonce="n-1")
    _cast(q, "a2", a, "APPROVE", nonce="n-1")


# ----------------------------------------------- F3: ballot stuffing


def test_f3_one_agent_repeating_approve_cannot_fake_quorum():
    q = ByzantineQuorum(min_nodes=1, threshold=1.0, clock=_clock_at(T0))
    (a,) = _agents(1)
    for _ in range(4):
        _cast(q, "act", a, "APPROVE")
    assert len(q.votes["act"]) == 1
    assert q.check_quorum("act") is False


def test_f3_revote_replaces_previous_ballot():
    q = ByzantineQuorum(clock=_clock_at(T0))
    ids = _agents(4)
    for a in ids:
        _cast(q, "act", a, "APPROVE")
    assert q.check_quorum("act") is True
    _cast(q, "act", ids[0], "REJECT")
    _cast(q, "act", ids[1], "REJECT")
    assert q.check_quorum("act") is False


# ------------------------------------------- F4: expiry in the denominator


def test_f4_expired_votes_leave_the_denominator():
    q = ByzantineQuorum(min_nodes=2, threshold=0.9, clock=_clock_at(T0))
    ids = _agents(4)
    _cast(q, "act", ids[0], "REJECT", ts=T0 - 29)
    _cast(q, "act", ids[1], "REJECT", ts=T0 - 29)
    _cast(q, "act", ids[2], "APPROVE", ts=T0)
    _cast(q, "act", ids[3], "APPROVE", ts=T0)
    q._clock = _clock_at(T0 + 5)
    assert q.check_quorum("act") is True


# ------------------------------------------------ F5: trust registry works


def test_f5_injected_trust_scores_take_effect():
    reg = TrustRegistry()
    ids = _agents(4)
    for a in ids:
        reg.set_score(a, 0.1)
    q = ByzantineQuorum(threshold=0.67, trust_registry=reg, clock=_clock_at(T0))
    for a in ids:
        _cast(q, "act", a, "APPROVE")
    assert q.check_quorum("act") is False
    for a in ids:
        reg.set_score(a, 0.9)
    assert q.check_quorum("act") is True


def test_f5_default_construction_keeps_legacy_weighting():
    q = ByzantineQuorum(clock=_clock_at(T0))
    for a in _agents(4):
        _cast(q, "act", a, "APPROVE")
    assert q.check_quorum("act") is True


# --------------------------------------------------- constructor guards


def test_constructor_rejects_degenerate_config():
    for kw in ({"threshold": 0}, {"min_nodes": 0}, {"expiry": 0}):
        with pytest.raises(ValueError):
            ByzantineQuorum(**kw)
