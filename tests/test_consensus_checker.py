"""ConsensusChecker: operator-pinned quorum over pv-vote/2 votes, wired at
the 'consensus' precedence level between policy and authorization.

The roster, the weights and the threshold are the operator's. The caller
supplies votes and nothing else, and every vote is bound to the action
under decision."""

import time

import pytest

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.consensus import (
    ConsensusChecker,
    ConsensusConfig,
    ConsensusConfigError,
)
from agent_dna.consensus.signing import (
    cast_vote_v2,
    consensus_action_id,
    generate_voter_keypair,
)
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.open_authorizer import OpenAuthorizer
from agent_dna.trace import AgentAction

AGENT, CAP = "a1", "settlement.execute"
ARGS = {"amount": 9_000_000, "payee_id": "V-100"}
KEYS = {name: generate_voter_keypair() for name in ("fraud", "finance", "legal")}
OUTSIDER = generate_voter_keypair()


class StubScorer:
    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.0,
            severity=Severity.INFO,
            reasons=[],
        )


def _config(threshold=2.0, required_for=(), **extra):
    return ConsensusConfig.from_dict(
        {
            "threshold": threshold,
            "voters": [
                {"agent_id": name, "weight": 1.0, "public_key": k["public_key"]}
                for name, k in KEYS.items()
            ],
            "required_for": list(required_for),
            **extra,
        }
    )


def _engine(config=None, **kwargs):
    return DecisionEngine(
        scorer=StubScorer(),
        consensus=ConsensusChecker(config, **kwargs),
        authorizer=OpenAuthorizer(),
    )


def _act(arguments=None, capability=CAP):
    return AgentAction(
        agent_id=AGENT,
        capability=capability,
        timestamp=time.time(),
        arguments=dict(ARGS if arguments is None else arguments),
    )


def _action_id(arguments=None, capability=CAP):
    return consensus_action_id(
        AGENT, capability, ARGS if arguments is None else arguments
    )


def _vote(name, value="APPROVE", action_id=None, key=None, **kwargs):
    return cast_vote_v2(
        (key or KEYS[name])["signing_key"],
        agent_id=name,
        action_id=action_id or _action_id(),
        vote=value,
        **kwargs,
    )


def _evidence(votes, action_id=None, **extra):
    return {
        "consensus": {"action_id": action_id or _action_id(), "votes": votes, **extra}
    }


# ---- evidence honesty ------------------------------------------------------


def test_no_evidence_skips():
    result = ConsensusChecker(_config()).check(evidence=None, capability=CAP)
    assert not result.flagged
    assert "quorum" in result.checks_skipped


def test_no_evidence_is_a_hold_where_the_operator_requires_a_quorum():
    engine = _engine(_config(required_for=["settlement."]))
    result = engine.decide(_act())
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert result.triggered_by == "consensus"
    assert "consensus_required" in result.reason
    # a capability outside required_for is untouched
    other = engine.decide(_act(capability="crm.read_contact"))
    assert other.decision is Decision.ALLOW


def test_evidence_without_a_pinned_roster_is_held_not_trusted():
    result = _engine(None).decide(
        _act(), evidence=_evidence([_vote("fraud"), _vote("finance")])
    )
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert result.triggered_by == "consensus"
    assert "consensus_not_configured" in result.reason


def test_no_checker_attached_means_no_consensus_level():
    engine = DecisionEngine(scorer=StubScorer(), authorizer=OpenAuthorizer())
    result = engine.decide(_act(), evidence=_evidence([]))
    assert result.triggered_by != "consensus"
    assert result.decision is Decision.ALLOW


# ---- a real quorum ---------------------------------------------------------


def test_quorum_clears_engine_allows():
    result = _engine(_config()).decide(
        _act(), evidence=_evidence([_vote("fraud"), _vote("finance")])
    )
    assert result.decision is Decision.ALLOW, result.reason


def test_quorum_shortfall_escalates_never_blocks():
    result = _engine(_config()).decide(
        _act(), evidence=_evidence([_vote("fraud"), _vote("finance", "REJECT")])
    )
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert result.triggered_by == "consensus"
    assert "quorum_shortfall" in result.reason


# ---- the caller cannot set the rules --------------------------------------


@pytest.mark.parametrize(
    "smuggled",
    [
        {"threshold": 1e-9},
        {"trust_scores": {"fraud": 1.0}},
        {"voters": [{"agent_id": "fraud", "weight": 99}]},
        {"weights": {"fraud": 99}},
    ],
)
def test_caller_supplied_threshold_or_weights_are_refused(smuggled):
    """One vote plus a caller-chosen threshold or weight used to clear."""
    result = _engine(_config()).decide(
        _act(), evidence=_evidence([_vote("fraud")], **smuggled)
    )
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert result.triggered_by == "consensus"
    assert "cannot be set by the caller" in result.reason


def test_one_approval_cannot_outvote_the_threshold():
    result = _engine(_config()).decide(_act(), evidence=_evidence([_vote("fraud")]))
    assert result.decision is Decision.REQUIRE_APPROVAL


def test_off_roster_voter_counts_zero():
    stranger = cast_vote_v2(
        OUTSIDER["signing_key"],
        agent_id="intern-bot",
        action_id=_action_id(),
        vote="APPROVE",
    )
    result = _engine(_config()).decide(
        _act(), evidence=_evidence([_vote("fraud"), stranger])
    )
    assert result.decision is Decision.REQUIRE_APPROVAL


def test_vote_signed_with_the_wrong_key_counts_zero():
    forged = _vote("finance", key=OUTSIDER)  # claims to be finance
    result = _engine(_config()).decide(
        _act(), evidence=_evidence([_vote("fraud"), forged])
    )
    assert result.decision is Decision.REQUIRE_APPROVAL


def test_one_voter_counts_once():
    result = _engine(_config()).decide(
        _act(), evidence=_evidence([_vote("fraud"), _vote("fraud")])
    )
    assert result.decision is Decision.REQUIRE_APPROVAL


# ---- votes are bound to the action under decision -------------------------


def test_votes_for_another_action_do_not_clear_this_one():
    """Votes cast for a coffee order used to clear any action."""
    coffee = consensus_action_id(AGENT, "office.order_coffee", {"amount": 4})
    votes = [_vote("fraud", action_id=coffee), _vote("finance", action_id=coffee)]
    engine = _engine(_config())
    # presented under their own action id
    mismatch = engine.decide(_act(), evidence=_evidence(votes, action_id=coffee))
    assert mismatch.decision is Decision.REQUIRE_APPROVAL
    assert "consensus_action_mismatch" in mismatch.reason
    # relabelled with this action's id: the signatures no longer verify
    relabelled = engine.decide(_act(), evidence=_evidence(votes))
    assert relabelled.decision is Decision.REQUIRE_APPROVAL
    assert "quorum_shortfall" in relabelled.reason


def test_changing_an_argument_voids_the_quorum():
    votes = [_vote("fraud"), _vote("finance")]
    changed = {**ARGS, "payee_id": "ATTACKER"}
    result = _engine(_config()).decide(_act(changed), evidence=_evidence(votes))
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert "consensus_action_mismatch" in result.reason


def test_a_cleared_quorum_cannot_be_replayed():
    engine = _engine(_config())
    evidence = _evidence([_vote("fraud"), _vote("finance")])
    assert engine.decide(_act(), evidence=evidence).decision is Decision.ALLOW
    again = engine.decide(_act(), evidence=evidence)
    assert again.decision is Decision.REQUIRE_APPROVAL
    assert again.triggered_by == "consensus"


def test_expired_and_overlong_votes_count_zero():
    now = time.time()
    expired = [_vote("fraud", now=now - 600), _vote("finance", now=now - 600)]
    result = _engine(_config()).decide(_act(), evidence=_evidence(expired))
    assert result.decision is Decision.REQUIRE_APPROVAL
    forever = [_vote("fraud", ttl=10**9), _vote("finance", ttl=10**9)]
    result = _engine(_config()).decide(_act(), evidence=_evidence(forever))
    assert result.decision is Decision.REQUIRE_APPROVAL


def test_a_reject_cannot_be_reread_as_an_approve():
    """A reviewer's REJECT is one signed JSON object; no re-split of the
    signed bytes yields an APPROVE."""
    reject = _vote("finance", "REJECT")
    flipped = {**reject, "vote": "APPROVE"}
    result = _engine(_config()).decide(
        _act(), evidence=_evidence([_vote("fraud"), flipped])
    )
    assert result.decision is Decision.REQUIRE_APPROVAL


@pytest.mark.parametrize(
    "consensus",
    [[], "x", {"action_id": 1, "votes": []}, {"votes": "x"}, {"votes": [1, None]}],
)
def test_malformed_evidence_is_a_hold_never_a_crash_or_a_pass(consensus):
    checker = ConsensusChecker(_config())
    evidence = {"consensus": consensus}
    if isinstance(consensus, dict) and "action_id" not in consensus:
        evidence["consensus"]["action_id"] = _action_id()
    result = checker.check(evidence, agent_id=AGENT, capability=CAP, arguments=ARGS)
    assert result.flagged


# ---- the operator's configuration is validated at load --------------------


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda c: c.update(threshold=0), "positive"),
        (lambda c: c.update(threshold=99), "exceeds total voter weight"),
        (lambda c: c.update(threshold=1.5), "not more than half"),
        (lambda c: c.update(voters=[]), "non-empty"),
        (lambda c: c.update(surprise=1), "unknown field"),
        (lambda c: c["voters"].append(dict(c["voters"][0])), "duplicate voter"),
        (lambda c: c["voters"][0].update(public_key="zz"), "public_key"),
        (lambda c: c["voters"][0].update(weight=-1), "weight"),
    ],
)
def test_bad_configuration_refuses_to_load(mutate, message):
    raw = {
        "threshold": 2.0,
        "voters": [
            {"agent_id": name, "weight": 1.0, "public_key": k["public_key"]}
            for name, k in KEYS.items()
        ],
    }
    mutate(raw)
    with pytest.raises(ConsensusConfigError, match=message):
        ConsensusConfig.from_dict(raw)


def test_minority_threshold_needs_an_explicit_opt_in():
    cfg = _config(threshold=1.0, allow_minority_threshold=True)
    assert cfg.threshold == 1.0
