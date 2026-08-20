"""Canonical monetary amount coercion.

Policy, grant-budget, and circuit-breaker paths must not parse amounts
with bare float(). Invalid values fail closed before any spent or
breaker-row mutation.
"""

from __future__ import annotations

import os
from decimal import Decimal, InvalidOperation

INVALID_AMOUNT = "INVALID_AMOUNT"
DEFAULT_AMOUNT_CEILING = Decimal("1000000000")
MAX_AMOUNT_FRACTIONAL_PLACES = 8
MAX_AMOUNT_DIGITS = 18
_CEILING_ENV = "PV_AMOUNT_ABSOLUTE_CEILING"


class InvalidAmountError(ValueError):
    """Rejected amount. reason_code is always INVALID_AMOUNT."""

    reason_code = INVALID_AMOUNT

    def __init__(self, detail: str) -> None:
        self.reason_code = INVALID_AMOUNT
        super().__init__(f"{INVALID_AMOUNT}: {detail}")


def amount_ceiling() -> Decimal:
    raw = os.environ.get(_CEILING_ENV)
    if raw is None or raw == "":
        return DEFAULT_AMOUNT_CEILING
    try:
        ceiling = Decimal(raw)
    except InvalidOperation as exc:
        raise InvalidAmountError(f"{_CEILING_ENV} is not a finite decimal") from exc
    if not ceiling.is_finite() or ceiling < 0:
        raise InvalidAmountError(f"{_CEILING_ENV} is not a finite non-negative decimal")
    return ceiling


def _parse_to_decimal(raw: object) -> Decimal:
    if raw is None or isinstance(raw, bool):
        raise InvalidAmountError(f"rejected {raw!r}")
    if isinstance(raw, Decimal):
        return raw
    if isinstance(raw, int):
        return Decimal(raw)
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            raise InvalidAmountError("empty string")
        try:
            return Decimal(text)
        except InvalidOperation as exc:
            raise InvalidAmountError(f"non-numeric {raw!r}") from exc
    if isinstance(raw, float):
        if raw != raw or raw == float("inf") or raw == float("-inf"):
            raise InvalidAmountError(f"non-finite {raw!r}")
        return Decimal(str(raw))
    raise InvalidAmountError(f"unsupported type {type(raw).__name__}")


def coerce_amount(raw: object) -> Decimal:
    """Return a finite, non-negative Decimal at or under the absolute ceiling.

    Rejects bool (bool is an int subclass), None, NaN, ±inf, negatives,
    non-numeric values, excessive fractional precision, oversized digit
    strings, and values above PV_AMOUNT_ABSOLUTE_CEILING.
    """
    value = _parse_to_decimal(raw)
    if not value.is_finite():
        raise InvalidAmountError(f"non-finite {raw!r}")
    if value < 0:
        raise InvalidAmountError(f"negative {raw!r}")
    _reject_excessive_precision(value)
    ceiling = amount_ceiling()
    if value > ceiling:
        raise InvalidAmountError(f"{value} exceeds absolute ceiling {ceiling}")
    return value


def _reject_excessive_precision(value: Decimal) -> None:
    exponent = value.as_tuple().exponent
    if not isinstance(exponent, int):
        raise InvalidAmountError(f"non-finite {value!r}")
    if exponent < -MAX_AMOUNT_FRACTIONAL_PLACES:
        raise InvalidAmountError(
            f"more than {MAX_AMOUNT_FRACTIONAL_PLACES} fractional digits"
        )
    if len(value.as_tuple().digits) > MAX_AMOUNT_DIGITS:
        raise InvalidAmountError(f"more than {MAX_AMOUNT_DIGITS} significant digits")
