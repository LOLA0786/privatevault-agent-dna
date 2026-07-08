"""Grant lifecycle: expiry, revocation, budget — each failure names
its condition. Built against external review findings (revocation and
time-boxing gaps)."""

import time

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.grants import GrantRegistry
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


def _engine(registry):
    return DecisionEngine(scorer=StubScorer(), authorizer=registry)


def _act(cap="payment.pay_invoice", amount=None):
    args = {"amount": amount} if amount is not None else {}
    return AgentAction(
        agent_id="agent-1", capability=cap,
        timestamp=time.time(), arguments=args,
    )


def test_valid_grant_allows():
    reg = GrantRegistry()
    reg.grant(agent_id="agent-1", capability="payment.pay_invoice",
              granted_by="cfo@corp")
    assert _engine(reg).decide(_act()).decision == Decision.ALLOW


def test_no_grant_names_the_gap():
    result = _engine(GrantRegistry()).decide(_act())
    assert result.decision == Decision.REQUIRE_APPROVAL
    assert "no grant exists" in result.reason


def test_expired_grant_blocks_with_reason():
    reg = GrantRegistry()
    reg.grant(agent_id="agent-1", capability="payment.pay_invoice",
              granted_by="cfo@corp", expires_at=time.time() - 60)
    result = _engine(reg).decide(_act())
    assert result.decision == Decision.REQUIRE_APPROVAL
    assert "expired" in result.reason


def test_revoked_grant_blocks_with_reason():
    reg = GrantRegistry()
    g = reg.grant(agent_id="agent-1", capability="payment.pay_invoice",
                  granted_by="cfo@corp")
    assert _engine(reg).decide(_act()).decision == Decision.ALLOW  # before

    reg.revoke(g.grant_id, revoked_by="security@corp")
    result = _engine(reg).decide(_act())                            # after
    assert result.decision == Decision.REQUIRE_APPROVAL
    assert "revoked by security@corp" in result.reason


def test_budget_exceeded_names_amounts():
    reg = GrantRegistry()
    g = reg.grant(agent_id="agent-1", capability="payment.pay_invoice",
                  granted_by="cfo@corp", budget=10000.0)
    ok = _engine(reg).decide(_act(amount=6000.0))
    assert ok.decision == Decision.ALLOW
    reg.record_spend(g.grant_id, 6000.0)

    result = _engine(reg).decide(_act(amount=6000.0))
    assert result.decision == Decision.REQUIRE_APPROVAL
    assert "budget exceeded" in result.reason


def test_revocation_history_reconstructable_from_records():
    """The audit claim: decisions before and after revocation carry
    distinguishable reasons — revocation history reconstructs from the
    record stream alone."""
    from agent_dna.decision_recorder import DecisionRecorder

    reg = GrantRegistry()
    g = reg.grant(agent_id="agent-1", capability="payment.pay_invoice",
                  granted_by="cfo@corp")
    engine = _engine(reg)
    recorder = DecisionRecorder()

    a1 = _act()
    recorder.record(a1, engine.decide(a1))
    reg.revoke(g.grant_id, revoked_by="security@corp")
    a2 = _act()
    recorder.record(a2, engine.decide(a2))

    recs = recorder.graph.find_by_agent("agent-1")
    assert recs[0].decision == "allow"
    assert recs[1].decision == "require_approval"
    assert "revoked" in recs[1].reason
    assert recorder.graph.verify_chain("agent-1")
