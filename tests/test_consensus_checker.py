"""ConsensusChecker: evidence-gated multi-agent quorum, wired at the
new 'consensus' precedence level between invariant and authorization."""

import time

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.consensus import ConsensusChecker
from agent_dna.consensus.signing import register_key, sign_message
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.trace import AgentAction


class StubScorer:
    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.0,
            severity=Severity.INFO,
            reasons=[],
        )


def _engine():
    return DecisionEngine(scorer=StubScorer(), consensus=ConsensusChecker())


def _act():
    return AgentAction(
        agent_id="a1", capability="settlement.execute", timestamp=time.time()
    )


def _signed_votes(agents_and_votes, action_id, message_hash):
    from agent_dna.consensus.signing import cast_vote

    votes = []
    for agent_id, vote in agents_and_votes:
        register_key(agent_id, f"secret-{agent_id}")
        votes.append(cast_vote(agent_id, action_id, vote, message_hash))
    return votes


def test_no_evidence_skips():
    checker = ConsensusChecker()
    result = checker.check(evidence=None)
    assert not result.flagged
    assert "quorum" in result.checks_skipped


def test_quorum_clears_engine_allows():
    votes = _signed_votes(
        [("a", "APPROVE"), ("b", "APPROVE")],
        "act-1",
        "h1",
    )
    engine = _engine()
    result = engine.decide(
        _act(),
        evidence={
            "consensus": {
                "action_id": "act-1",
                "threshold": 0.67,
                "votes": votes,
                "trust_scores": {"a": 0.5, "b": 0.5},
            }
        },
    )
    assert result.decision == Decision.ALLOW


def test_quorum_shortfall_escalates_never_blocks():
    votes = _signed_votes([("a", "REJECT")], "act-2", "h2")
    engine = _engine()
    result = engine.decide(
        _act(),
        evidence={
            "consensus": {
                "action_id": "act-2",
                "threshold": 0.67,
                "votes": votes,
                "trust_scores": {"a": 1.0},
            }
        },
    )
    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.triggered_by == "consensus"
    assert "quorum_shortfall" in result.reason


def test_forged_vote_does_not_inflate_quorum():
    """Same guarantee as the standalone consensus module, now proven
    through the full engine path."""
    register_key("real-agent", "real-secret")
    register_key("attacker", "attacker-secret")
    forged_sig = sign_message("attacker", "h3")
    votes = [
        {
            "agent_id": "real-agent",
            "vote": "APPROVE",
            "signature": forged_sig,
            "message_hash": "h3",
        }
    ]
    engine = _engine()
    result = engine.decide(
        _act(),
        evidence={
            "consensus": {
                "action_id": "act-3",
                "threshold": 0.5,
                "votes": votes,
                "trust_scores": {"real-agent": 1.0},
            }
        },
    )
    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.triggered_by == "consensus"


def test_no_checker_attached_means_no_consensus_level():
    engine = DecisionEngine(scorer=StubScorer())  # consensus=None
    result = engine.decide(
        _act(),
        evidence={
            "consensus": {
                "action_id": "act-4",
                "threshold": 0.99,
                "votes": [],
            }
        },
    )
    assert result.triggered_by != "consensus"
    assert result.decision == Decision.ALLOW
