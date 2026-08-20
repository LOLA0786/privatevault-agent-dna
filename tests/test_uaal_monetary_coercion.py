"""PV-06: UAAL monetary conservation uses Decimal coercion, not float()."""

from __future__ import annotations

from decimal import Decimal

import pytest

from agent_dna.amount import INVALID_AMOUNT
from agent_dna.intent_adapter import intent_to_action
from agent_dna.uaal_layer import UAALConstraintChecker

C = UAALConstraintChecker()


def _pay(amount) -> object:
    return intent_to_action(
        actor_id="payment-agent-01",
        verb="pay_invoice",
        target={"type": "payment", "id": "INV-1001"},
        parameters={"amount": amount},
        timestamp=1.0,
    )


def _evidence(invoice_amount) -> dict:
    return {
        "user_request": {"canonical_target": "INV-1001"},
        "planner": {"canonical_target": "INV-1001"},
        "approvals": {"required": False},
        "enterprise_state": {
            "invoice_amount": invoice_amount,
            "invoice_open": True,
            "target_verified": True,
            "duplicate": False,
        },
    }


def _monetary(result):
    return next(d for d in result.detail if d["name"] == "monetary_conservation")


@pytest.mark.parametrize(
    "raw",
    [float("inf"), float("-inf"), float("nan"), -1, True, False, "not-a-number"],
)
def test_invalid_action_amount_is_malformed_not_mismatch(raw) -> None:
    result = C.check(_pay(raw), evidence=_evidence(0))
    assert result.violated
    monetary = _monetary(result)
    assert monetary["passed"] is False
    assert "mismatch" not in monetary["reason"]
    assert "malformed" in monetary["reason"] or INVALID_AMOUNT in monetary["reason"]


@pytest.mark.parametrize(
    "raw",
    [float("inf"), float("-inf"), float("nan"), -5, True, "nope"],
)
def test_invalid_invoice_amount_is_malformed_not_mismatch(raw) -> None:
    result = C.check(_pay(0), evidence=_evidence(raw))
    assert result.violated
    monetary = _monetary(result)
    assert monetary["passed"] is False
    assert "mismatch" not in monetary["reason"]
    assert "malformed" in monetary["reason"] or INVALID_AMOUNT in monetary["reason"]


def test_matching_inf_does_not_pass_conservation() -> None:
    result = C.check(_pay(float("inf")), evidence=_evidence(float("inf")))
    assert result.violated
    assert "mismatch" not in _monetary(result)["reason"]


def test_valid_zero_conserved() -> None:
    result = C.check(_pay(0), evidence=_evidence(0))
    assert not result.violated
    assert _monetary(result)["passed"] is True


def test_valid_decimal_conserved() -> None:
    result = C.check(_pay(Decimal("3.50")), evidence=_evidence(Decimal("3.50")))
    assert not result.violated
    assert _monetary(result)["passed"] is True


def test_decimal_mismatch_still_reports_mismatch() -> None:
    result = C.check(_pay(Decimal("3.50")), evidence=_evidence(Decimal("4.00")))
    assert result.violated
    assert _monetary(result)["reason"] == "amount mismatch"
