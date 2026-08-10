"""L0 UAAL constraints: precedence-0 blocking, evidence honesty,
intent adaptation. Scenario: invoice payment with amount tampering."""

import time

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.intent_adapter import intent_to_action
from agent_dna.open_authorizer import OpenAuthorizer
from agent_dna.uaal_layer import UAALConstraintChecker


class StubScorer:
    def __init__(self, drift=0.0):
        self.drift = drift

    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=self.drift,
            severity=Severity.INFO,
            reasons=[],
        )


class StubInvariants:
    def validate(self, capability, previous):
        class R:
            pass

        r = R()
        r.violated = False
        r.message = ""
        return r


def _engine(drift=0.0):
    return DecisionEngine(
        scorer=StubScorer(drift),
        invariants=StubInvariants(),
        uaal=UAALConstraintChecker(),
        authorizer=OpenAuthorizer(),
    )


def _pay(amount):
    return intent_to_action(
        actor_id="payment-agent-01",
        verb="pay_invoice",
        target={"type": "payment", "id": "INV-1001"},
        parameters={"amount": amount},
        confidence=0.95,
        timestamp=time.time(),
    )


EVIDENCE = {
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


def test_honest_payment_passes_l0():
    result = _engine().decide(_pay(5000.0), evidence=EVIDENCE)
    assert result.decision == Decision.ALLOW


def test_amount_tampering_blocked_at_l0():
    """Agent tries to pay 49,000 against a 5,000 invoice —
    monetary_conservation fires, triggered_by is uaal_constraint."""
    result = _engine().decide(_pay(49000.0), evidence=EVIDENCE)
    assert result.decision == Decision.BLOCK
    assert result.triggered_by == "uaal_constraint"
    assert "monetary_conservation" in result.reason


def test_identity_drift_blocked_at_l0():
    """Planner redirected the target — user asked INV-1001, tool aims
    at INV-9999."""
    action = intent_to_action(
        actor_id="payment-agent-01",
        verb="pay_invoice",
        target={"type": "payment", "id": "INV-9999"},
        parameters={"amount": 5000.0},
        timestamp=time.time(),
    )
    result = _engine().decide(action, evidence=EVIDENCE)
    assert result.decision == Decision.BLOCK
    assert "identity_preservation" in result.reason


def test_l0_wins_precedence_over_drift():
    """drift=0.90 would REQUIRE_APPROVAL; the L0 violation must BLOCK
    and be attributed to uaal_constraint, not drift."""
    result = _engine(drift=0.90).decide(_pay(49000.0), evidence=EVIDENCE)
    assert result.decision == Decision.BLOCK
    assert result.triggered_by == "uaal_constraint"


def test_missing_evidence_skips_not_fails():
    """No evidence supplied: only capability_preservation is checkable.
    The action must NOT be blocked by unverifiable invariants."""
    checker = UAALConstraintChecker()
    r = checker.check(_pay(49000.0), evidence=None)
    assert not r.violated
    assert "capability_preservation" in r.checks_run
    assert "monetary_conservation" in r.checks_skipped
    assert "identity_preservation" in r.checks_skipped


def test_no_uaal_slot_means_no_l0():
    engine = DecisionEngine(
        scorer=StubScorer(),
        invariants=StubInvariants(),
        authorizer=OpenAuthorizer(),
    )
    result = engine.decide(_pay(49000.0), evidence=EVIDENCE)
    assert result.decision == Decision.ALLOW  # nothing checks amounts
