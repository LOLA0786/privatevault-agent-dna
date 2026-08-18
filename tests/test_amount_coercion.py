"""Invalid amounts must not bypass grant budgets or breaker caps.

Reproduced: negative spend, NaN-poisoned spent, and bool/inf/garbage
coercion through float(). Rejection is BLOCK with INVALID_AMOUNT,
before any spent/breaker mutation.
"""

from __future__ import annotations

import math
import time
from decimal import Decimal

import pytest

from agent_dna.amount import (
    DEFAULT_AMOUNT_CEILING,
    INVALID_AMOUNT,
    InvalidAmountError,
    coerce_amount,
)
from agent_dna.circuit_breaker import BreakerConfig, CircuitBreaker, GuardedEngine
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.grants import GrantRegistry
from agent_dna.open_authorizer import OpenAuthorizer
from agent_dna.trace import AgentAction
from tests.test_p0_audit import StubScorer

CAP = "payments.initiate_wire"
AGENT = "amt-agent"


def _act(amount, *, agent_id: str = AGENT, capability: str = CAP) -> AgentAction:
    return AgentAction(
        agent_id=agent_id,
        capability=capability,
        timestamp=time.time(),
        arguments={"amount": amount},
    )


def _grant_engine(budget: float = 100.0) -> tuple[GrantRegistry, DecisionEngine]:
    reg = GrantRegistry()
    reg.grant(agent_id=AGENT, capability=CAP, granted_by="cfo", budget=budget)
    return reg, DecisionEngine(scorer=StubScorer(), authorizer=reg)


def _guarded_grant(
    tmp_path, budget: float = 100.0
) -> tuple[GrantRegistry, GuardedEngine]:
    reg, engine = _grant_engine(budget)
    breaker = CircuitBreaker(
        tmp_path / "grant-breaker.db",
        BreakerConfig(
            max_decisions=None,
            max_cumulative_amount=None,
            max_consecutive_refusals=None,
        ),
    )
    return reg, GuardedEngine(engine, breaker)


def _guarded_breaker(tmp_path, cap: float = 100.0) -> GuardedEngine:
    breaker = CircuitBreaker(
        tmp_path / "vol-breaker.db",
        BreakerConfig(
            max_decisions=None,
            max_cumulative_amount=cap,
            max_consecutive_refusals=None,
        ),
    )
    engine = DecisionEngine(scorer=StubScorer(), authorizer=OpenAuthorizer())
    return GuardedEngine(engine, breaker)


def _assert_invalid_block(result) -> None:
    assert result.decision is Decision.BLOCK
    assert INVALID_AMOUNT in result.reason


@pytest.mark.parametrize(
    "raw",
    [
        True,
        False,
        float("nan"),
        float("inf"),
        float("-inf"),
        -1,
        -1000,
        "-1000",
        "NaN",
        "Infinity",
        "-Infinity",
        "not-a-number",
        object(),
        None,
        DEFAULT_AMOUNT_CEILING + 1,
    ],
)
def test_coerce_amount_rejects_invalid(raw) -> None:
    with pytest.raises(InvalidAmountError) as excinfo:
        coerce_amount(raw)
    assert excinfo.value.reason_code == INVALID_AMOUNT


def test_coerce_amount_accepts_finite_non_negative() -> None:
    assert coerce_amount(0) == Decimal("0")
    assert coerce_amount(100) == Decimal("100")
    assert coerce_amount("50.25") == Decimal("50.25")
    assert coerce_amount(Decimal("3.50")) == Decimal("3.50")


def test_grant_limit_blocks_1000() -> None:
    _reg, engine = _grant_engine(100.0)
    result = engine.decide(_act(1000))
    assert result.decision is not Decision.ALLOW
    assert "budget exceeded" in result.reason


def test_negative_spend_does_not_open_grant_budget(tmp_path) -> None:
    """grant limit 100 blocks 1000; recording -1000 must not let 1000 pass."""
    reg, guarded = _guarded_grant(tmp_path, budget=100.0)
    blocked = guarded.decide(_act(1000))
    assert blocked.decision is not Decision.ALLOW
    spent_before = Decimal(str(reg._grants[next(iter(reg._grants))].spent))

    negative = guarded.decide(_act(-1000))
    _assert_invalid_block(negative)
    grant = next(iter(reg._grants.values()))
    assert Decimal(str(grant.spent)) == spent_before

    with pytest.raises(InvalidAmountError):
        reg.record_spend(grant.grant_id, -1000)
    assert Decimal(str(grant.spent)) == spent_before

    still = guarded.decide(_act(1000))
    assert still.decision is not Decision.ALLOW
    assert Decimal(str(grant.spent)) == spent_before


def test_breaker_cap_rejects_negative_then_holds_limit(tmp_path) -> None:
    """circuit-breaker cap 100 must not allow -1000 then +1000."""
    guarded = _guarded_breaker(tmp_path, cap=100.0)
    negative = guarded.decide(_act(-1000))
    _assert_invalid_block(negative)
    follow = guarded.decide(_act(1000))
    assert follow.decision is Decision.BLOCK
    assert follow.decision is not Decision.ALLOW


def test_nan_does_not_poison_spent(tmp_path) -> None:
    """'NaN' must not poison spent; any later amount still faces the limit."""
    reg, guarded = _guarded_grant(tmp_path, budget=100.0)
    grant = next(iter(reg._grants.values()))
    spent_before = Decimal(str(grant.spent))

    nan_result = guarded.decide(_act("NaN"))
    _assert_invalid_block(nan_result)
    assert Decimal(str(grant.spent)) == spent_before

    with pytest.raises(InvalidAmountError):
        reg.record_spend(grant.grant_id, float("nan"))
    assert Decimal(str(grant.spent)) == spent_before
    assert not isinstance(grant.spent, float) or not math.isnan(float(grant.spent))

    still = guarded.decide(_act(1000))
    assert still.decision is not Decision.ALLOW
    assert Decimal(str(grant.spent)) == spent_before


def test_bool_inf_string_block_without_spend(tmp_path) -> None:
    reg, guarded = _guarded_grant(tmp_path, budget=100.0)
    grant = next(iter(reg._grants.values()))
    spent_before = Decimal(str(grant.spent))
    for raw in (True, float("inf"), "nope"):
        result = guarded.decide(_act(raw))
        _assert_invalid_block(result)
        assert Decimal(str(grant.spent)) == spent_before
    allowed = guarded.decide(_act(40))
    assert allowed.decision is Decision.ALLOW
    blocked = guarded.decide(_act(1000))
    assert blocked.decision is not Decision.ALLOW
