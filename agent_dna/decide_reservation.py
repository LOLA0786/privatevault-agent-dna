"""Decide-time reservation of a business transaction (ADR 0041).

Policy rules that stop a duplicate (``duplicate-refund``) read what has
already been paid. Two decides for the same refund, taken before either is
paid, both see nothing paid and both seal an ALLOW. Each ALLOW mints its own
permit. A receiver that names a transaction key (ADR 0030, ADR 0040) admits
only one, but the server has still vouched twice for one transaction.

With ``PV_DECIDE_TRANSACTION_KEYS`` set, the server reserves the transaction
when it seals a mintable ALLOW and blocks a second ALLOW for the same
transaction while the first can still execute:

    PV_DECIDE_TRANSACTION_KEYS='{"POST /v1/refunds": "refund_id"}'

The mapping is from the sealed dispatch operation (``METHOD path``) to a
dotted field of the sealed ``execution_action.parameters``; the same shape
as the receiver's ``PV_RECEIVER_TRANSACTION_KEYS``.

A reservation is held until the first decision's authority can no longer
mint a valid permit: ``decision_window_seconds`` after the decide (a permit
never outlives that, ADR 0024), plus a small clock margin. It is not
released early. A consumed permit, a refused dispatch or an expired permit
all leave it in place until that time, because the server cannot see what
the receiver did. After it lapses a new decide is judged on its own; by then
a paid refund is visible to the policy.

What this is not: it is not exactly-once execution, it does not replace the
receiver's transaction key, and the key is only as good as the field named.
Unset, nothing is reserved and decide behaves as before.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_dna.advisory import Severity
from agent_dna.decision import Decision, DecisionResult
from agent_dna.pg_compat import PgCompatConnection

RESERVATION_ENV = "PV_DECIDE_TRANSACTION_KEYS"
TRIGGERED_BY_RESERVATION = "transaction_reservation"
TRANSACTION_RESERVED = "TRANSACTION_RESERVED"
TRANSACTION_KEY_MISSING = "TRANSACTION_KEY_MISSING"
# Added to the hold so a mint host whose clock runs slightly behind the
# decide host cannot mint after the reservation has lapsed.
CLOCK_MARGIN_SECONDS = 5

_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS decide_reservations (
    operation    TEXT NOT NULL,
    key_digest   TEXT NOT NULL,
    holder       TEXT NOT NULL,
    decision_id  TEXT,
    reserved_at  REAL NOT NULL,
    expires_at   REAL NOT NULL,
    PRIMARY KEY (operation, key_digest)
);
"""


class ReservationConfigError(ValueError):
    """``PV_DECIDE_TRANSACTION_KEYS`` is malformed. The server does not start."""


def reservation_keys_from_env(env: Mapping[str, str]) -> dict[str, str]:
    """``{"METHOD path": "dotted.field"}``, or ``{}`` when unset."""
    raw = str(env.get(RESERVATION_ENV, "") or "").strip()
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except ValueError as exc:
        raise ReservationConfigError(f"{RESERVATION_ENV} is not JSON: {exc}") from None
    if not isinstance(value, dict) or not value:
        raise ReservationConfigError(
            f'{RESERVATION_ENV} must map "METHOD path" to a parameter field, '
            'e.g. {"POST /v1/refunds": "refund_id"}'
        )
    keys: dict[str, str] = {}
    for operation, field in value.items():
        if not isinstance(operation, str) or not isinstance(field, str):
            raise ReservationConfigError(
                f"{RESERVATION_ENV}: operation and field must be strings"
            )
        method, _, path = operation.partition(" ")
        if method not in _METHODS or not path.startswith("/") or " " in path:
            raise ReservationConfigError(
                f"{RESERVATION_ENV}: {operation!r} is not a write operation "
                '("POST /path")'
            )
        parts = field.split(".")
        if not field or any(not part for part in parts):
            raise ReservationConfigError(
                f"{RESERVATION_ENV}: {field!r} is not a dotted field name"
            )
        keys[operation] = field
    return keys


@dataclass(frozen=True)
class ReservationFinding:
    code: str
    detail: str


@dataclass(frozen=True)
class TransactionKey:
    operation: str
    field: str
    key_digest: str


def _lookup(parameters: Any, field: str) -> Any:
    value = parameters
    for part in field.split("."):
        if not isinstance(value, Mapping) or part not in value:
            return None
        value = value[part]
    return value


def transaction_key_for(
    keys: Mapping[str, str],
    execution_action: Mapping[str, Any],
    dispatch_context: Mapping[str, Any],
) -> TransactionKey | ReservationFinding | None:
    """The transaction this sealed action names, a finding when the operation
    declares a key and the action does not carry a usable one, or None when
    the operation declares no key."""
    operation = str(dispatch_context.get("operation", ""))
    field = keys.get(operation)
    if field is None:
        return None
    value = _lookup(execution_action.get("parameters"), field)
    usable = (isinstance(value, str) and value.strip() != "") or (
        isinstance(value, int) and not isinstance(value, bool)
    )
    if not usable:
        return ReservationFinding(
            TRANSACTION_KEY_MISSING,
            f"{operation} declares transaction key {field!r} and the action "
            "does not carry a non-empty string or integer there",
        )
    # Type-tagged so the string "7" and the integer 7 are different keys.
    material = json.dumps(
        [operation, type(value).__name__, value],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    digest = "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()
    return TransactionKey(operation=operation, field=field, key_digest=digest)


@dataclass(frozen=True)
class Claim:
    granted: bool
    holder: str
    decision_id: str | None
    expires_at: float


class DecideReservations:
    """One live reservation per (operation, transaction key), next to the
    decision store: the same SQLite file, or the same PostgreSQL database
    through a PgCompatConnection, so every replica sees it."""

    def __init__(self, path: str | Path | PgCompatConnection) -> None:
        self._pg = path if isinstance(path, PgCompatConnection) else None
        self.path = None if self._pg is not None else Path(str(path))
        self._local = threading.local()
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    @property
    def _conn(self) -> Any:  # sqlite3.Connection or PgCompatConnection
        if self._pg is not None:
            return self._pg
        conn = getattr(self._local, "conn", None)
        if conn is None:
            assert self.path is not None
            conn = sqlite3.connect(self.path, timeout=30)
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return conn

    def close(self) -> None:
        if self._pg is not None:  # the pool belongs to the decision store
            self._pg.rollback()
            return
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    def claim(
        self, key: TransactionKey, *, holder: str, now: float, hold_seconds: float
    ) -> Claim:
        """Atomically reserve ``key`` for ``holder`` until ``now +
        hold_seconds``. Granted when nothing holds it or the holder's
        reservation has lapsed; otherwise the live reservation is returned."""
        if hold_seconds <= 0:
            raise ValueError("hold_seconds must be positive")
        conn = self._conn
        expires_at = now + hold_seconds
        try:
            cur = conn.execute(
                "INSERT INTO decide_reservations "
                "(operation, key_digest, holder, decision_id, reserved_at, expires_at) "
                "VALUES (?, ?, ?, NULL, ?, ?) "
                "ON CONFLICT (operation, key_digest) DO UPDATE SET "
                "holder = excluded.holder, decision_id = NULL, "
                "reserved_at = excluded.reserved_at, "
                "expires_at = excluded.expires_at "
                "WHERE decide_reservations.expires_at <= excluded.reserved_at",
                (key.operation, key.key_digest, holder, now, expires_at),
            )
            granted = cur.rowcount == 1
            row = None
            if not granted:
                row = conn.execute(
                    "SELECT holder, decision_id, expires_at FROM decide_reservations "
                    "WHERE operation = ? AND key_digest = ?",
                    (key.operation, key.key_digest),
                ).fetchone()
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        if granted:
            return Claim(True, holder, None, expires_at)
        if row is None:  # lapsed and removed between the two statements
            return self.claim(key, holder=holder, now=now, hold_seconds=hold_seconds)
        return Claim(False, str(row[0]), row[1], float(row[2]))

    def attach(self, key: TransactionKey, *, holder: str, decision_id: str) -> None:
        """Name the sealed decision that holds the reservation."""
        conn = self._conn
        try:
            conn.execute(
                "UPDATE decide_reservations SET decision_id = ? "
                "WHERE operation = ? AND key_digest = ? AND holder = ?",
                (decision_id, key.operation, key.key_digest, holder),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def release(self, key: TransactionKey, *, holder: str) -> None:
        """Drop a reservation whose decision was never sealed (the record
        write failed). Never called for a sealed ALLOW."""
        conn = self._conn
        try:
            conn.execute(
                "DELETE FROM decide_reservations "
                "WHERE operation = ? AND key_digest = ? AND holder = ? "
                "AND decision_id IS NULL",
                (key.operation, key.key_digest, holder),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def escalate_with_reservation(
    result: DecisionResult, finding: ReservationFinding | None
) -> DecisionResult:
    """BLOCK on a finding. Never relaxes an existing verdict."""
    if finding is None or result.decision is Decision.BLOCK:
        return result
    return DecisionResult(
        decision=Decision.BLOCK,
        triggered_by=TRIGGERED_BY_RESERVATION,
        reason=f"{finding.code}: {finding.detail}",
        capability=result.capability,
        agent_id=result.agent_id,
        drift_score=result.drift_score,
        severity=Severity.CRITICAL,
        advisory_reasons=list(result.advisory_reasons),
        evidence=result.evidence,
        grant_id=result.grant_id,
    )


def reservation_manifest(keys: Mapping[str, str], attached: bool) -> dict[str, Any]:
    return {
        "enabled": bool(keys) and attached,
        "operations": sorted(keys),
        "note": (
            "a second ALLOW for the same transaction is blocked while the "
            "first can still mint"
            if keys and attached
            else "off: two decides for one transaction can both be allowed"
        ),
    }
