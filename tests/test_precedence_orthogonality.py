"""Precedence orthogonality: when MULTIPLE levels would independently
fire on the same action, the highest-precedence (lowest order number)
level must win — not just when only one level is violated at a time.

Every other test in this suite exercises levels in isolation. This
file constructs actions that would trigger two or three levels
simultaneously and confirms the winner is always the one earliest in
the committed precedence contract."""

import time

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.economics import CostAnomalyChecker
from agent_dna.grants import GrantRegistry
from agent_dna.trace import AgentAction
from agent_dna.uaal_layer import UAALConstraintChecker


class HighDriftScorer:
    """Always reports high drift — so L4 WOULD fire if nothing above
    it short-circuited first."""

    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.95,
            severity=Severity.CRITICAL,
            reasons=["always novel for this test"],
        )


class Invariants:
    def validate(self, capability, previous):
        class R:
            pass

        r = R()
        r.violated = capability == "storage.bulk_export"
        r.message = "invariant: bulk export forbidden" if r.violated else ""
        return r


HONEST_EVIDENCE = {
    "user_request": {"canonical_target": "INV-1001"},
    "planner": {"canonical_target": "INV-1001"},
    "approvals": {"required": False},
    "enterprise_state": {
        "invoice_amount": 5000.0,
        "invoice_open": True,
        "target_verified": True,
        "duplicate": False,
    },
}


def _full_engine():
    """Every level active simultaneously — the real deployment shape,
    not a stripped-down single-checker engine."""
    return DecisionEngine(
        scorer=HighDriftScorer(),
        invariants=Invariants(),
        authorizer=GrantRegistry(),  # empty — nothing granted
        uaal=UAALConstraintChecker(),
        economics=CostAnomalyChecker(),
    )


def _act(cap, args=None):
    return AgentAction(
        agent_id="orth-agent",
        capability=cap,
        timestamp=time.time(),
        arguments=args or {},
    )


def test_l0_wins_over_l3_l4_when_all_three_would_fire():
    """Tampered amount (L0 violation) + no grant (L2 would fire) +
    high drift (L4 would fire). L0 must win — earliest in the
    contract, not the loudest signal."""
    engine = _full_engine()
    action = _act("payment.pay_invoice", {"amount": 49000.0})
    result = engine.decide(action, evidence=HONEST_EVIDENCE)
    assert result.decision == Decision.BLOCK
    assert result.triggered_by == "uaal_constraint"


def test_l1_wins_over_l2_l3_l4_when_all_four_would_fire():
    """Forbidden capability (L1) + no grant (L2) + high drift (L4).
    No evidence supplied, so L0 skips (not violates) and L3 skips
    (no economics evidence) -- L1 must still win over L2 and L4."""
    engine = _full_engine()
    action = _act("storage.bulk_export")
    result = engine.decide(action, evidence=None)
    assert result.decision == Decision.BLOCK
    assert result.triggered_by == "invariant"


def test_l2_wins_over_l3_l4_when_no_l0_l1_violation():
    """Clean capability, no grant (L2 fires), cost anomaly present
    (L3 would also fire), high drift (L4 would also fire). L2 must
    win as the earliest REQUIRE_APPROVAL-class level."""
    engine = _full_engine()
    action = _act("crm.read_contact")
    result = engine.decide(
        action,
        evidence={
            "economics": {
                "estimated_cost_usd": 500.0,
                "historical_avg_cost_usd": 0.01,
            }
        },
    )
    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.triggered_by == "authorization"


def test_l3_wins_over_l4_when_granted_but_cost_anomalous():
    """Grant exists (L2 clears) + cost anomaly (L3 fires) + high
    drift (L4 would also fire). L3 must win over L4."""
    reg = GrantRegistry()
    reg.grant(agent_id="orth-agent", capability="crm.read_contact", granted_by="test")
    engine = DecisionEngine(
        scorer=HighDriftScorer(),
        invariants=Invariants(),
        authorizer=reg,
        uaal=UAALConstraintChecker(),
        economics=CostAnomalyChecker(),
    )
    action = _act("crm.read_contact")
    result = engine.decide(
        action,
        evidence={
            "economics": {
                "estimated_cost_usd": 500.0,
                "historical_avg_cost_usd": 0.01,
            }
        },
    )
    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.triggered_by == "economics"


def test_l4_only_wins_when_nothing_above_it_fires():
    """Grant exists, no cost evidence supplied, high drift. L4 is
    the only level with anything to say -- confirms the chain
    actually reaches the last probabilistic level rather than always
    stopping early by accident."""
    reg = GrantRegistry()
    reg.grant(agent_id="orth-agent", capability="crm.read_contact", granted_by="test")
    engine = DecisionEngine(
        scorer=HighDriftScorer(),
        invariants=Invariants(),
        authorizer=reg,
        uaal=UAALConstraintChecker(),
    )  # no economics checker attached at all
    action = _act("crm.read_contact")
    result = engine.decide(action, evidence=None)
    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.triggered_by == "drift"


def test_consensus_wins_over_authorization_economics_drift():
    """Quorum shortfall + no grant + cost anomaly + high drift, all
    would independently fire. Consensus (order 2) must win over
    authorization (3), economics (4), drift (5)."""
    from agent_dna.consensus import ConsensusChecker
    from agent_dna.consensus.signing import cast_vote, register_key
    from agent_dna.economics import CostAnomalyChecker

    register_key("a", "secret-a")
    votes = [cast_vote("a", "x", "REJECT", "hh")]

    engine = DecisionEngine(
        scorer=HighDriftScorer(),
        invariants=Invariants(),
        authorizer=GrantRegistry(),  # empty
        uaal=UAALConstraintChecker(),
        economics=CostAnomalyChecker(),
        consensus=ConsensusChecker(),
    )
    action = _act("crm.read_contact")
    result = engine.decide(
        action,
        evidence={
            "consensus": {
                "action_id": "x",
                "threshold": 0.9,
                "votes": votes,
                "trust_scores": {"a": 1.0},
            },
            "economics": {"estimated_cost_usd": 500.0, "historical_avg_cost_usd": 0.01},
        },
    )
    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.triggered_by == "consensus"


def test_l1_invariant_still_wins_over_consensus():
    """Forbidden capability (L1) + quorum shortfall (consensus) both
    would fire. L1 must still win — it's earlier and it's a BLOCK."""
    from agent_dna.consensus import ConsensusChecker
    from agent_dna.consensus.signing import cast_vote, register_key

    register_key("a", "secret-a")
    votes = [cast_vote("a", "y", "REJECT", "hh2")]

    engine = DecisionEngine(
        scorer=HighDriftScorer(),
        invariants=Invariants(),
        authorizer=GrantRegistry(),
        uaal=UAALConstraintChecker(),
        consensus=ConsensusChecker(),
    )
    action = _act("storage.bulk_export")
    result = engine.decide(
        action,
        evidence={
            "consensus": {
                "action_id": "y",
                "threshold": 0.9,
                "votes": votes,
                "trust_scores": {"a": 1.0},
            },
        },
    )
    assert result.decision == Decision.BLOCK
    assert result.triggered_by == "invariant"
