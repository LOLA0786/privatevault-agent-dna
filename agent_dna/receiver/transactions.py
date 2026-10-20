"""One business transaction, one admitted effect (ADR 0030).

A permit is single-use, but a new decision for the same invoice mints a new
permit (follow-up review, 20 October 2026, item 2). The receiver operator
therefore declares, per write operation, which field of the request body
identifies the business transaction (an invoice number, a payment
reference). The gate reads that field from the bytes the permit binds and
claims ``(organisation, operation, key)`` in the same ledger transaction as
the permit. A second permit for a claimed key is refused, whoever minted
it.

A claim then moves through these states:

``CLAIMED``
    Admitted and handed to the upstream; no answer recorded yet. A crash
    between admission and the upstream's answer leaves the claim here.
``EXECUTED``
    The upstream answered 2xx.
``NOT_EXECUTED``
    The upstream answered with a status that means the request was not
    acted on (``NOT_EXECUTED_STATUSES``), or an operator reconciled it so.
    Only this state lets a new permit claim the key again.
``INDETERMINATE``
    The upstream failed, timed out, or answered anything else. Like
    ``CLAIMED`` it blocks the key until an operator reconciles it against
    the system of record (``tools/receiver_transactions.py``).

Every state change is appended to an event history in the same ledger.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from agent_dna.authority_v01 import strict_json_loads

CLAIMED = "CLAIMED"
EXECUTED = "EXECUTED"
NOT_EXECUTED = "NOT_EXECUTED"
INDETERMINATE = "INDETERMINATE"
STATES = frozenset({CLAIMED, EXECUTED, NOT_EXECUTED, INDETERMINATE})
# States an operator may reconcile, and what they may reconcile them to.
OPEN_STATES = frozenset({CLAIMED, INDETERMINATE})
RESOLUTIONS = frozenset({EXECUTED, NOT_EXECUTED})

# Upstream answers taken to mean "not acted on": malformed, unauthorised,
# unknown route or method, unsupported type, unprocessable. Deliberately not
# 408, 409, 425, 429 or any 5xx: those can follow a partial or completed
# effect, so they leave the claim INDETERMINATE.
NOT_EXECUTED_STATUSES = frozenset({400, 401, 403, 404, 405, 415, 422})

MAX_KEY_LENGTH = 256
_SAFE_INT = 2**53 - 1


class TransactionKeyError(ValueError):
    """The body does not carry a usable transaction key."""


def classify_upstream(status: int | None) -> str:
    """The claim state an upstream answer leaves. ``None``: no answer."""
    if status is None:
        return INDETERMINATE
    if 200 <= status < 300:
        return EXECUTED
    if status in NOT_EXECUTED_STATUSES:
        return NOT_EXECUTED
    return INDETERMINATE


def validate_field_path(field_path: str) -> tuple[str, ...]:
    parts = tuple(field_path.split("."))
    if not field_path or not all(p and p.isprintable() for p in parts):
        raise ValueError(f"transaction key field is not a dotted path: {field_path!r}")
    return parts


def extract_transaction_key(body: bytes, field_path: str) -> str:
    """The value at ``field_path`` (dotted, objects only) in a JSON body.

    A string of 1..256 printable characters, or a safe integer (rendered in
    decimal). Anything else is a TransactionKeyError."""
    try:
        document: Any = strict_json_loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise TransactionKeyError(
            f"body is not strict JSON (I-JSON, no floats): {exc}"
        ) from None
    value: Any = document
    for part in validate_field_path(field_path):
        if not isinstance(value, Mapping) or part not in value:
            raise TransactionKeyError(f"body has no {field_path!r}")
        value = value[part]
    if isinstance(value, bool):
        raise TransactionKeyError(f"{field_path!r} is a boolean")
    if isinstance(value, int):
        if abs(value) > _SAFE_INT:
            raise TransactionKeyError(f"{field_path!r} is not a safe integer")
        return str(value)
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_KEY_LENGTH
        or not value.isprintable()
        or value != value.strip()
    ):
        raise TransactionKeyError(
            f"{field_path!r} must be a non-empty trimmed string of at most "
            f"{MAX_KEY_LENGTH} printable characters, or an integer"
        )
    return value


def transaction_reference(organisation_id: str, operation: str, key: str) -> str:
    """Stable, opaque reference for one transaction, suitable as an upstream
    ``Idempotency-Key``: the upstream can deduplicate without learning the
    organisation or operation, and the receiver can map it back."""
    material = "\x00".join((organisation_id, operation, key)).encode("utf-8")
    return "pvtx-" + hashlib.sha256(material).hexdigest()
