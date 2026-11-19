"""Decide-time daily limits per business key (ADR 0043).

Policy rules such as "at most 3 refunds per customer per day" read a count
the caller computed before deciding. Concurrent decides each read the same
count: five refunds fired at once for one customer all saw 0 and were all
allowed (Rs 99,995 against a limit of three). This module keeps the count
and the amount on the server and claims them atomically when a mintable
ALLOW is sealed:

    PV_DECIDE_LIMITS='{"POST /v1/refunds": {"key": "customer_id",
        "max_count": 3, "max_amount": 60000, "utc_offset_minutes": 330}}'

For each declared operation, ``key`` names a dotted field of the sealed
``execution_action.parameters`` (who the limit is per), ``amount_field``
(default ``amount``) the amount, and the window is the calendar day at
``utc_offset_minutes`` (default 0, UTC).

- ``max_count``: an ALLOW that would be the key's (max_count+1)th today is a
  BLOCK. An approval does not lift it.
- ``max_amount``: an ALLOW that would take the key's total today above it is
  a BLOCK unless the ALLOW was granted by a human approval. Holding a refund
  FOR approval is the policy's job (a rule on the caller's daily total); this
  is the backstop for when that total was stale.

A claim is all or nothing (one conditional UPDATE on the key's row for the
day), shared by every replica using the database, and released if the
decision is not sealed. What it counts is what this server allowed: refunds
made outside it are not seen.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from agent_dna.pg_compat import PgCompatConnection

LIMITS_ENV = "PV_DECIDE_LIMITS"
TRIGGERED_BY_LIMIT = "decide_limit"
DAILY_COUNT_LIMIT = "DAILY_COUNT_LIMIT"
DAILY_AMOUNT_LIMIT = "DAILY_AMOUNT_LIMIT"
DECIDE_LIMIT_INPUT_MISSING = "DECIDE_LIMIT_INPUT_MISSING"

_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_KEYS = {"key", "max_count", "max_amount", "amount_field", "utc_offset_minutes"}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS decide_limits (
    operation   TEXT NOT NULL,
    key_digest  TEXT NOT NULL,
    day         TEXT NOT NULL,
    count       BIGINT NOT NULL,
    amount      BIGINT NOT NULL,
    PRIMARY KEY (operation, key_digest, day)
);
"""


class LimitConfigError(ValueError):
    """``PV_DECIDE_LIMITS`` is malformed. The server does not start."""


@dataclass(frozen=True)
class Limit:
    operation: str
    key: str
    max_count: int | None
    max_amount: float | None
    amount_field: str = "amount"
    utc_offset_minutes: int = 0


def _dotted(name: Any) -> bool:
    return isinstance(name, str) and bool(name) and all(name.split("."))


def limits_from_env(env: Mapping[str, str]) -> dict[str, Limit]:  # noqa: C901 - checklist
    raw = str(env.get(LIMITS_ENV, "") or "").strip()
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except ValueError as exc:
        raise LimitConfigError(f"{LIMITS_ENV} is not JSON: {exc}") from None
    if not isinstance(value, dict) or not value:
        raise LimitConfigError(f'{LIMITS_ENV} must map "METHOD path" to a limit')
    limits: dict[str, Limit] = {}
    for operation, spec in value.items():
        method, _, path = str(operation).partition(" ")
        if method not in _METHODS or not path.startswith("/") or " " in path:
            raise LimitConfigError(
                f"{LIMITS_ENV}: {operation!r} is not a write operation"
            )
        if not isinstance(spec, dict) or not set(spec) <= _KEYS or "key" not in spec:
            raise LimitConfigError(
                f'{LIMITS_ENV}: {operation}: an object with "key" and any of '
                f"{sorted(_KEYS - {'key'})}"
            )
        count, amount = spec.get("max_count"), spec.get("max_amount")
        if count is None and amount is None:
            raise LimitConfigError(
                f"{LIMITS_ENV}: {operation}: set max_count or max_amount"
            )
        if count is not None and (
            isinstance(count, bool) or not isinstance(count, int) or count < 1
        ):
            raise LimitConfigError(f"{LIMITS_ENV}: {operation}: max_count must be >= 1")
        if amount is not None and (
            isinstance(amount, bool)
            or not isinstance(amount, (int, float))
            or not amount > 0
        ):
            raise LimitConfigError(f"{LIMITS_ENV}: {operation}: max_amount must be > 0")
        offset = spec.get("utc_offset_minutes", 0)
        if (
            isinstance(offset, bool)
            or not isinstance(offset, int)
            or not -720 <= offset <= 840
        ):
            raise LimitConfigError(
                f"{LIMITS_ENV}: {operation}: utc_offset_minutes must be -720..840"
            )
        field = spec.get("amount_field", "amount")
        if not _dotted(spec["key"]) or not _dotted(field):
            raise LimitConfigError(
                f"{LIMITS_ENV}: {operation}: key and amount_field are dotted names"
            )
        limits[str(operation)] = Limit(
            operation=str(operation),
            key=spec["key"],
            max_count=count,
            max_amount=float(amount) if amount is not None else None,
            amount_field=field,
            utc_offset_minutes=offset,
        )
    return limits


def _lookup(parameters: Any, field: str) -> Any:
    value = parameters
    for part in field.split("."):
        if not isinstance(value, Mapping) or part not in value:
            return None
        value = value[part]
    return value


def minor_units(amount: float) -> int:
    return int(round(float(amount) * 100))


@dataclass(frozen=True)
class Subject:
    """Which row a decision counts against, and how much it adds."""

    limit: Limit
    key_value: Any
    key_digest: str
    day: str
    amount: int  # minor units


def subject_for(
    limit: Limit, execution_action: Mapping[str, Any], now: datetime
) -> Subject | str:
    """The row this sealed action counts against, or why it cannot count."""
    parameters = execution_action.get("parameters")
    key_value = _lookup(parameters, limit.key)
    if not (
        (isinstance(key_value, str) and key_value.strip())
        or (isinstance(key_value, int) and not isinstance(key_value, bool))
    ):
        return f"{limit.operation} counts per {limit.key!r} and the action carries none"
    raw_amount = _lookup(parameters, limit.amount_field)
    if limit.max_amount is not None and (
        isinstance(raw_amount, bool)
        or not isinstance(raw_amount, (int, float))
        or not raw_amount >= 0
    ):
        return f"{limit.operation} limits {limit.amount_field!r} and the action states no valid amount"
    amount = minor_units(raw_amount) if isinstance(raw_amount, (int, float)) else 0
    material = json.dumps(
        [limit.operation, type(key_value).__name__, key_value], separators=(",", ":")
    )
    digest = "sha256:" + hashlib.sha256(material.encode()).hexdigest()
    local = now.astimezone(UTC) + timedelta(minutes=limit.utc_offset_minutes)
    return Subject(limit, key_value, digest, local.strftime("%Y-%m-%d"), amount)


@dataclass(frozen=True)
class Claim:
    subject: Subject


@dataclass(frozen=True)
class Refusal:
    code: str
    detail: str


class DecideLimits:
    """One row per (operation, key, day), next to the decision store."""

    def __init__(self, path: str | Path | PgCompatConnection) -> None:
        self._pg = path if isinstance(path, PgCompatConnection) else None
        self.path = None if self._pg is not None else Path(str(path))
        self._local = threading.local()
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    @property
    def _conn(self) -> Any:
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
        if self._pg is not None:
            self._pg.rollback()
            return
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    def claim(self, subject: Subject, *, approved: bool) -> Claim | Refusal:
        """Count one more decision and its amount, or refuse with which limit."""
        limit = subject.limit
        pk = (limit.operation, subject.key_digest, subject.day)
        conditions, params = [], [subject.amount, *pk]
        if limit.max_count is not None:
            conditions.append("count + 1 <= ?")
            params.append(limit.max_count)
        check_amount = limit.max_amount is not None and not approved
        if check_amount:
            assert limit.max_amount is not None
            conditions.append("amount + ? <= ?")
            params += [subject.amount, minor_units(limit.max_amount)]
        where = " AND ".join(
            ["operation = ? AND key_digest = ? AND day = ?", *conditions]
        )
        conn = self._conn
        try:
            conn.execute(
                "INSERT INTO decide_limits (operation, key_digest, day, count, amount) "
                "VALUES (?, ?, ?, 0, 0) ON CONFLICT (operation, key_digest, day) DO NOTHING",
                pk,
            )
            cur = conn.execute(
                f"UPDATE decide_limits SET count = count + 1, amount = amount + ? WHERE {where}",
                params,
            )
            if cur.rowcount == 1:
                conn.commit()
                return Claim(subject)
            count, amount = conn.execute(
                "SELECT count, amount FROM decide_limits "
                "WHERE operation = ? AND key_digest = ? AND day = ?",
                pk,
            ).fetchone()
            conn.rollback()
        except Exception:
            conn.rollback()
            raise
        who = f"{limit.key} {subject.key_value!r}"
        if limit.max_count is not None and count + 1 > limit.max_count:
            return Refusal(
                DAILY_COUNT_LIMIT,
                f"{who} already has {count} of {limit.max_count} allowed on {subject.day}",
            )
        assert limit.max_amount is not None
        return Refusal(
            DAILY_AMOUNT_LIMIT,
            f"{who} has {amount / 100:g} of {limit.max_amount:g} allowed on "
            f"{subject.day}; {subject.amount / 100:g} more needs a human approval",
        )

    def release(self, claim: Claim) -> None:
        """Give back a claim whose decision was never sealed."""
        s = claim.subject
        conn = self._conn
        try:
            conn.execute(
                "UPDATE decide_limits SET count = count - 1, amount = amount - ? "
                "WHERE operation = ? AND key_digest = ? AND day = ?",
                (s.amount, s.limit.operation, s.key_digest, s.day),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def usage(self, subject: Subject) -> tuple[int, int]:
        row = self._conn.execute(
            "SELECT count, amount FROM decide_limits "
            "WHERE operation = ? AND key_digest = ? AND day = ?",
            (subject.limit.operation, subject.key_digest, subject.day),
        ).fetchone()
        self._conn.commit()
        return (0, 0) if row is None else (int(row[0]), int(row[1]))


def limits_manifest(limits: Mapping[str, Limit], attached: bool) -> dict[str, Any]:
    return {
        "enabled": bool(limits) and attached,
        "operations": {
            op: {
                "per": lim.key,
                "max_count": lim.max_count,
                "max_amount": lim.max_amount,
                "day_utc_offset_minutes": lim.utc_offset_minutes,
            }
            for op, lim in sorted(limits.items())
        },
    }
