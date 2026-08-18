"""Audit set 4: one grant model, grant lineage into records, budgets
that actually decrement, deprecation of the parallel implementations."""

import time

import pytest

from agent_dna.circuit_breaker import (
    BreakerConfig,
    CircuitBreaker,
    GuardedEngine,
)
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.grants import GrantRegistry
from agent_dna.trace import AgentAction
from tests.test_p0_audit import StubScorer


def _engine(registry):
    return DecisionEngine(scorer=StubScorer(), authorizer=registry)


def _act(cap="payments.initiate_wire", amount=None):
    args = {} if amount is None else {"amount": amount}
    return AgentAction(
        agent_id="grantee-1", capability=cap, timestamp=time.time(), arguments=args
    )


def test_grant_id_flows_into_result_and_record(tmp_path):
    reg = GrantRegistry()
    g = reg.grant(
        agent_id="grantee-1", capability="payments.initiate_wire", granted_by="cfo"
    )
    engine = _engine(reg)
    result = engine.decide(_act())
    assert result.decision is Decision.ALLOW
    assert result.grant_id == g.grant_id

    rec = DecisionRecorder().record(_act(), result)
    assert rec.approval_ref == g.grant_id, (
        "the schema-reserved approval_ref must carry the grant the "
        "action executed under"
    )


def test_no_grant_result_has_no_approval_ref():
    result = _engine(GrantRegistry()).decide(_act())
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert result.triggered_by == "authorization"
    assert result.grant_id is None
    rec = DecisionRecorder().record(_act(), result)
    assert rec.approval_ref is None


def test_budget_actually_decrements_across_actions(tmp_path):
    """record_spend existed but was wired into nothing: budgets were
    checked against a ledger nobody wrote to, so a 100-budget grant
    approved unlimited 60-unit payments forever."""
    reg = GrantRegistry()
    reg.grant(
        agent_id="grantee-1",
        capability="payments.initiate_wire",
        granted_by="cfo",
        budget=100.0,
    )
    breaker = CircuitBreaker(
        tmp_path / "b.db",
        BreakerConfig(
            max_decisions=None,
            max_cumulative_amount=None,
            max_consecutive_refusals=None,
        ),
    )
    guarded = GuardedEngine(_engine(reg), breaker)

    first = guarded.decide(_act(amount=60.0))
    assert first.decision is Decision.ALLOW

    second = guarded.decide(_act(amount=60.0))  # 60 spent + 60 > 100
    assert second.decision is Decision.REQUIRE_APPROVAL
    assert second.triggered_by == "authorization"
    assert "budget exceeded" in second.reason


def test_malformed_amount_fails_authorization_closed():
    reg = GrantRegistry()
    reg.grant(
        agent_id="grantee-1",
        capability="payments.initiate_wire",
        granted_by="cfo",
        budget=100.0,
    )
    result = _engine(reg).decide(_act(amount="not-a-number"))
    assert result.decision is Decision.BLOCK
    assert "INVALID_AMOUNT" in result.reason


def test_failing_spend_ledger_fails_closed(tmp_path):
    class BrokenLedger(GrantRegistry):
        def record_spend(self, grant_id, amount):
            raise RuntimeError("ledger unavailable")

    reg = BrokenLedger()
    reg.grant(
        agent_id="grantee-1", capability="payments.initiate_wire", granted_by="cfo"
    )
    breaker = CircuitBreaker(
        tmp_path / "b2.db",
        BreakerConfig(
            max_decisions=None,
            max_cumulative_amount=None,
            max_consecutive_refusals=None,
        ),
    )
    result = GuardedEngine(_engine(reg), breaker).decide(_act(amount=10.0))
    assert result.decision is Decision.BLOCK
    assert "grant_spend_fault" in result.reason


def test_parallel_implementations_warn_deprecated():
    with pytest.warns(DeprecationWarning):
        from agent_dna.allowlist import CapabilityRegistry

        CapabilityRegistry()
    with pytest.warns(DeprecationWarning):
        from agent_dna.authorization import AuthorizationPolicy

        AuthorizationPolicy()
