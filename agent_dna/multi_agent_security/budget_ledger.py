"""Cumulative delegation budgets (ADR 0042).

A pv-delegation/2 link may carry a ``budget``: the most that may be spent,
in total, under that link, by its delegate and by everyone it delegates to.
``max_amount`` caps one action; a budget caps them all.

When a decision under a verified chain is ALLOWED, the server charges the
amount to every budgeted link of the chain in ONE transaction: each charge is
a conditional ``UPDATE ... WHERE spent + amount <= budget``. If any link would
go over, nothing is charged and the decision is a BLOCK. Concurrent charges on
the same link serialize on its row, so siblings spending from their parent's
pool, on any number of replicas sharing the database, cannot together exceed
it.

Amounts are kept in integer minor units (x100), so repeated charges do not
drift. A charge is released only if the decision it paid for is not sealed
(a later control blocked it, or the record write failed). A sealed ALLOW
keeps its charge even if the permit is never minted or the payment never
runs: the budget counts authority used, not money moved.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_dna.pg_compat import PgCompatConnection

_SCHEMA = """
CREATE TABLE IF NOT EXISTS delegation_spend (
    link_hash  TEXT PRIMARY KEY,
    budget     BIGINT NOT NULL,
    spent      BIGINT NOT NULL
);
"""


def minor_units(amount: float) -> int:
    return int(round(float(amount) * 100))


@dataclass(frozen=True)
class Charge:
    """What one allowed decision took from each budgeted link."""

    entries: tuple[tuple[str, int], ...]  # (link hash, budget in minor units)
    amount: int  # minor units


@dataclass(frozen=True)
class Exhausted:
    link_hash: str
    budget: int
    spent: int
    amount: int

    def reason(self, index: int | None = None) -> str:
        where = f"link {index}" if index is not None else f"link {self.link_hash[:16]}"
        return (
            f"delegation_budget_exceeded: {where} has spent "
            f"{self.spent / 100:g} of its {self.budget / 100:g} budget; "
            f"{self.amount / 100:g} more would exceed it"
        )


class DelegationBudgets:
    """One row per budgeted link, next to the decision store: the same SQLite
    file, or the shared PostgreSQL database."""

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

    def charge(
        self, budgets: Sequence[tuple[str, float]], amount: float
    ) -> Charge | Exhausted:
        """Charge ``amount`` to every budgeted link, all or nothing."""
        units = minor_units(amount)
        entries = tuple((h, minor_units(b)) for h, b in budgets)
        if units < 0:
            raise ValueError("amount must be >= 0")
        conn = self._conn
        try:
            for link, budget in entries:
                conn.execute(
                    "INSERT INTO delegation_spend (link_hash, budget, spent) "
                    "VALUES (?, ?, 0) ON CONFLICT (link_hash) DO NOTHING",
                    (link, budget),
                )
                cur = conn.execute(
                    "UPDATE delegation_spend SET spent = spent + ? "
                    "WHERE link_hash = ? AND spent + ? <= budget",
                    (units, link, units),
                )
                if cur.rowcount != 1:
                    row = conn.execute(
                        "SELECT budget, spent FROM delegation_spend WHERE link_hash = ?",
                        (link,),
                    ).fetchone()
                    conn.rollback()
                    return Exhausted(link, int(row[0]), int(row[1]), units)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        return Charge(entries, units)

    def release(self, charge: Charge) -> None:
        """Give back a charge whose decision was never sealed."""
        conn = self._conn
        try:
            for link, _budget in charge.entries:
                conn.execute(
                    "UPDATE delegation_spend SET spent = spent - ? WHERE link_hash = ?",
                    (charge.amount, link),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def spent(self, link: str) -> int | None:
        row = self._conn.execute(
            "SELECT spent FROM delegation_spend WHERE link_hash = ?", (link,)
        ).fetchone()
        self._conn.commit()
        return None if row is None else int(row[0])
