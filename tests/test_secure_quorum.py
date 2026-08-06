"""SecureQuorum + pv-vote/1 signing. Preserves every property of the
pre-P0-6 suite (forged/unsigned rejection, trust weighting, honest
summing, unknown actions, defaults) and adds the P0-6 contracts:
one vote per voter, nonce single-use, action binding, expiry."""

import pytest

from agent_dna.consensus.secure_quorum import SecureQuorum, TrustRegistry
from agent_dna.consensus.signing import (
    cast_vote,
    register_key,
    sign_message,
    verify_signature,
)

NOW = 1000.0
_clock = [NOW]


# ---- raw signing primitive (unchanged semantics) ----------------------


def test_valid_signature_verifies():
    register_key("agent-a", "secret-a")
    sig = sign_message("agent-a", "h1")
    assert verify_signature("agent-a", "h1", sig)


def test_forged_signature_is_rejected():
    register_key("agent-a", "secret-a")
    register_key("agent-b", "secret-b")
    forged = sign_message("agent-b", "h1")
    assert not verify_signature("agent-a", "h1", forged)


def test_signature_over_different_hash_is_rejected():
    register_key("agent-a", "secret-a")
    sig = sign_message("agent-a", "h1")
    assert not verify_signature("agent-a", "h2", sig)


def test_unregistered_agent_fails_closed_not_crashes():
    """Original source would raise on .encode() of None for an
    unregistered agent. Fixed to fail closed (False), not crash."""
    assert not verify_signature("nobody", "h", "sig")


# ---- quorum ------------------------------------------------------------


def _quorum(threshold, tr, now=NOW):
    return SecureQuorum(threshold=threshold, trust_registry=tr, clock=lambda: now)


def _vote(agent, action, vote="APPROVE", h="h", now=NOW, ttl=300.0):
    register_key(agent, f"secret-{agent}")
    return cast_vote(agent, action, vote, h, ttl=ttl, now=now)


def test_quorum_ignores_unsigned_forged_votes():
    tr = TrustRegistry()
    tr.set_score("attacker", 1.0)  # trust irrelevant if sig is forged
    tr.set_score("honest-agent", 1.0)
    register_key("honest-agent", "secret-honest")
    register_key("attacker", "secret-attacker")

    q = _quorum(0.67, tr)
    forged = _vote("attacker", "action-1")
    forged["agent_id"] = "honest-agent"  # impersonation attempt
    assert not q.submit("action-1", forged)
    assert not q.check_quorum("action-1")

    assert q.submit("action-1", _vote("honest-agent", "action-1"))
    assert q.check_quorum("action-1")  # honest alone clears


def test_quorum_respects_trust_weighted_threshold():
    tr = TrustRegistry()
    tr.set_score("low-trust", 0.3)
    q = _quorum(0.67, tr)
    assert q.submit("a1", _vote("low-trust", "a1"))
    assert not q.check_quorum("a1")  # 0.3 < 0.67


def test_quorum_sums_multiple_honest_approvers():
    tr = TrustRegistry()
    tr.set_score("h1", 0.4)
    tr.set_score("h2", 0.4)
    q = _quorum(0.67, tr)
    q.submit("x", _vote("h1", "x"))
    q.submit("x", _vote("h2", "x"))
    assert q.check_quorum("x")  # 0.8 >= 0.67


def test_reject_votes_do_not_contribute_score():
    tr = TrustRegistry()
    tr.set_score("r1", 1.0)
    q = _quorum(0.5, tr)
    q.submit("x", _vote("r1", "x", vote="REJECT"))
    assert not q.check_quorum("x")


def test_unknown_action_id_has_no_quorum():
    q = _quorum(0.5, TrustRegistry())
    assert not q.check_quorum("never-submitted")


def test_default_trust_score_applies_when_unset():
    q = _quorum(0.5, TrustRegistry())
    q.submit("x", _vote("unscored", "x"))
    assert q.check_quorum("x")  # default 0.5 >= 0.5


# ---- P0-6 contracts ----------------------------------------------------


def test_one_voter_cannot_vote_twice():
    tr = TrustRegistry()
    tr.set_score("solo", 0.3)
    q = _quorum(0.67, tr)
    v = _vote("solo", "action-1")
    assert q.submit("action-1", v)
    assert not q.submit("action-1", v)  # duplicate ignored
    assert not q.submit("action-1", _vote("solo", "action-1"))  # re-vote too
    assert not q.check_quorum("action-1"), (
        "one agent with trust 0.3 achieved a 0.67 quorum by voting 3x"
    )


def test_vote_cannot_replay_across_actions():
    tr = TrustRegistry()
    tr.set_score("honest", 1.0)
    q = _quorum(0.5, tr)
    v = _vote("honest", "action-1", h="shared-hash")
    assert q.submit("action-1", v)
    assert q.check_quorum("action-1")  # legitimate

    assert not q.submit("action-2", v)  # bound to action-1
    assert not q.check_quorum("action-2"), (
        "a vote cast for action-1 was replayed to approve action-2"
    )


def test_expired_vote_is_rejected_at_submit_and_count():
    tr = TrustRegistry()
    tr.set_score("h1", 1.0)

    q = _quorum(0.5, tr, now=NOW)
    stale = _vote("h1", "x", now=NOW - 1000.0, ttl=300.0)
    assert not q.submit("x", stale)  # already expired

    # valid at submit, expired by count time
    q2 = SecureQuorum(0.5, tr, clock=lambda: _clock[0])
    _clock[0] = NOW
    assert q2.submit("y", _vote("h1", "y", now=NOW, ttl=10.0))
    _clock[0] = NOW + 60.0
    assert not q2.check_quorum("y")


def test_future_dated_vote_rejected():
    tr = TrustRegistry()
    tr.set_score("h1", 1.0)
    q = _quorum(0.5, tr, now=NOW)
    assert not q.submit("x", _vote("h1", "x", now=NOW + 3600.0))


def test_nonce_single_use_per_action():
    tr = TrustRegistry()
    tr.set_score("h1", 0.5)
    tr.set_score("h2", 0.5)
    q = _quorum(0.9, tr)
    v1 = _vote("h1", "x")
    assert q.submit("x", v1)
    v2 = _vote("h2", "x")
    v2["nonce"] = v1["nonce"]  # reuse -- sig breaks anyway
    assert not q.submit("x", v2)


def test_invalid_trust_score_rejected():
    with pytest.raises(ValueError):
        TrustRegistry().set_score("a", 1.5)
    with pytest.raises(ValueError):
        TrustRegistry().set_score("a", -0.1)


def test_invalid_threshold_rejected():
    with pytest.raises(ValueError):
        SecureQuorum(0.0, TrustRegistry())
    with pytest.raises(ValueError):
        SecureQuorum(float("nan"), TrustRegistry())


def test_malformed_vote_is_zero_weight_not_crash():
    tr = TrustRegistry()
    tr.set_score("h1", 1.0)
    q = _quorum(0.5, tr)
    assert not q.submit("x", {"agent_id": "h1"})  # missing everything
    assert not q.submit("x", {})  # empty
    assert not q.check_quorum("x")
