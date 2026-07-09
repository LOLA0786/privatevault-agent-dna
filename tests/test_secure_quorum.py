"""Fresh tests for the vendored SecureQuorum + signing — zero tests
existed for these components in the source repo. Priority: prove the
signature verification actually rejects forgeries, since that's the
specific claim ('cryptographic signature verification') that matters
most and was completely unverified before this."""

import pytest

from agent_dna.consensus.secure_quorum import SecureQuorum, TrustRegistry
from agent_dna.consensus.signing import (
    register_key, sign_message, verify_signature,
)


def test_valid_signature_verifies():
    register_key("agent-1", "secret-key-1")
    sig = sign_message("agent-1", "hash-abc")
    assert verify_signature("agent-1", "hash-abc", sig)


def test_forged_signature_is_rejected():
    """The core claim under test: you cannot vote as an agent without
    that agent's key."""
    register_key("agent-1", "secret-key-1")
    register_key("attacker", "attacker-secret")
    forged = sign_message("attacker", "hash-abc")
    assert not verify_signature("agent-1", "hash-abc", forged)


def test_signature_over_different_hash_is_rejected():
    register_key("agent-1", "secret-key-1")
    sig = sign_message("agent-1", "hash-abc")
    assert not verify_signature("agent-1", "hash-DIFFERENT", sig)


def test_unregistered_agent_fails_closed_not_crashes():
    """Original source would raise on .encode() of None for an
    unregistered agent. Fixed to fail closed (False), not crash."""
    assert not verify_signature("never-registered", "h", "s")


def test_quorum_ignores_unsigned_forged_votes():
    tr = TrustRegistry()
    tr.set_score("honest-agent", 1.0)
    tr.set_score("attacker", 1.0)   # high trust score is irrelevant if signature is forged
    register_key("honest-agent", "real-secret")

    q = SecureQuorum(threshold=0.67, trust_registry=tr)
    real_sig = sign_message("honest-agent", "action-1-hash")
    q.submit_vote("action-1", "honest-agent", "APPROVE", real_sig, "action-1-hash")

    # attacker forges a vote AS "honest-agent" without knowing its key
    forged_sig = sign_message("attacker", "action-1-hash")
    q.submit_vote("action-1", "honest-agent", "APPROVE", forged_sig, "action-1-hash")

    # only the one genuinely-signed vote counts; forged one is dropped
    assert q.check_quorum("action-1")  # honest-agent alone (trust=1.0) clears 0.67
    # confirm it's not double-counted
    tr.set_score("honest-agent", 0.5)
    q2 = SecureQuorum(threshold=0.67, trust_registry=tr)
    q2.submit_vote("action-1", "honest-agent", "APPROVE", real_sig, "action-1-hash")
    q2.submit_vote("action-1", "honest-agent", "APPROVE", forged_sig, "action-1-hash")
    assert not q2.check_quorum("action-1")  # 0.5 < 0.67, forged vote didn't add weight


def test_quorum_respects_trust_weighted_threshold():
    tr = TrustRegistry()
    tr.set_score("low-trust", 0.3)
    register_key("low-trust", "secret")

    q = SecureQuorum(threshold=0.67, trust_registry=tr)
    sig = sign_message("low-trust", "h")
    q.submit_vote("a1", "low-trust", "APPROVE", sig, "h")
    assert not q.check_quorum("a1")  # 0.3 < 0.67


def test_quorum_sums_multiple_honest_approvers():
    tr = TrustRegistry()
    tr.set_score("a", 0.4)
    tr.set_score("b", 0.4)
    register_key("a", "sa")
    register_key("b", "sb")

    q = SecureQuorum(threshold=0.67, trust_registry=tr)
    q.submit_vote("x", "a", "APPROVE", sign_message("a", "h"), "h")
    q.submit_vote("x", "b", "APPROVE", sign_message("b", "h"), "h")
    assert q.check_quorum("x")  # 0.4 + 0.4 = 0.8 >= 0.67


def test_reject_votes_do_not_contribute_score():
    tr = TrustRegistry()
    tr.set_score("a", 1.0)
    register_key("a", "sa")

    q = SecureQuorum(threshold=0.5, trust_registry=tr)
    q.submit_vote("x", "a", "REJECT", sign_message("a", "h"), "h")
    assert not q.check_quorum("x")


def test_unknown_action_id_has_no_quorum():
    tr = TrustRegistry()
    q = SecureQuorum(threshold=0.5, trust_registry=tr)
    assert not q.check_quorum("never-submitted")


def test_default_trust_score_applies_when_unset():
    tr = TrustRegistry()  # no scores set
    register_key("a", "sa")
    q = SecureQuorum(threshold=0.5, trust_registry=tr)
    q.submit_vote("x", "a", "APPROVE", sign_message("a", "h"), "h")
    assert q.check_quorum("x")  # default 0.5 >= threshold 0.5
