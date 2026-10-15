"""Durable grant spend (security review 2026-10, "before live payments").

Grant budgets were held in process memory: a restart, or a second worker,
started every budget from zero, restoring spending authority that had
already been consumed. This ledger keeps spend in the decision store's
SQLite file and commits it with a check-and-add inside ``BEGIN IMMEDIATE``,
the same construction the circuit breaker uses, so every worker sharing the
database sees one budget.

Amounts are stored as canonical decimal strings, never floats.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from decimal import Decimal
from pathlib import Path

from .amount import coerce_amount

_SCHEMA = """
CREATE TABLE IF NOT EXISTS grant_spend (
    grant_id   TEXT PRIMARY KEY,
    spent      TEXT NOT NULL,
    updated_at REAL NOT NULL
);
"""


class GrantBudgetExceededError(ValueError):
    """The spend would exceed the grant's budget at commit time."""


class GrantSpendLedger:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._local = threading.local()
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    @property
    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=30)
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    def spent(self, grant_id: str) -> Decimal:
        row = self._conn.execute(
            "SELECT spent FROM grant_spend WHERE grant_id = ?", (grant_id,)
        ).fetchone()
        return Decimal(row[0]) if row else Decimal("0")

    def commit_spend(
        self, grant_id: str, amount: object, budget: object | None
    ) -> Decimal:
        """Atomically add ``amount``; raise if it would exceed ``budget``.

        Returns the new cumulative spend. Serialized across threads and
        processes by SQLite's write lock.
        """
        delta = coerce_amount(amount)
        conn = self._conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            row = conn.execute(
                "SELECT spent FROM grant_spend WHERE grant_id = ?", (grant_id,)
            ).fetchone()
            current = Decimal(row[0]) if row else Decimal("0")
            new = current + delta
            if budget is not None and new > coerce_amount(budget):
                raise GrantBudgetExceededError(
                    f"grant {grant_id[:14]} budget exceeded at commit "
                    f"({new} > {coerce_amount(budget)})"
                )
            conn.execute(
                "INSERT INTO grant_spend (grant_id, spent, updated_at) "
                "VALUES (?, ?, ?) ON CONFLICT(grant_id) DO UPDATE SET "
                "spent = excluded.spent, updated_at = excluded.updated_at",
                (grant_id, str(new), time.time()),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        return new
