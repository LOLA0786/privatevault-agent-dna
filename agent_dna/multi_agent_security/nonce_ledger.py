"""
Single-use ledger for cleared quorums.

A quorum that has cleared one decision must not clear a second. Tracking
that in process memory holds for one process only: with several API replicas
behind a load balancer the same votes clear once per replica.

``SqliteNonceLedger`` puts the record in one SQLite file. Every process that
opens the same file shares it, and ``consume`` is one transaction: either
every vote in the quorum is recorded as used, or none is and the caller is
told the quorum was already spent. Two replicas racing on the same votes
cannot both win.

``PostgresNonceLedger`` keeps the same table in PostgreSQL, for replicas on
separate hosts. The runtime uses it automatically when ``PV_DATABASE_URL``
is set.

Clocks. Each replica prunes with its own clock. If a used vote were dropped
the moment it expired, a replica whose clock runs ahead would drop it while
a slower replica still accepted the vote as fresh, and the quorum would
clear twice. A used vote is therefore kept for ``RETENTION_GRACE`` seconds
after it expires and counts as used for all that time, so a replay needs
two replica clocks more than that far apart.

Health. An unwritable or corrupt ledger cannot record a cleared quorum, so
it must not clear one. Opening the ledger proves it can be written to;
after that, any storage error raises ``LedgerUnavailable``, which the
checker turns into a hold with that reason, and ``health()`` reports it to
``/ready``.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Protocol

Entry = tuple[str, str, float]  # (agent_id, nonce, expires_at)


RETENTION_GRACE = 300.0


class LedgerUnavailable(RuntimeError):  # noqa: N818 - reads as the condition
    """The ledger cannot be read or written. Nothing may clear through it."""


class NonceLedger(Protocol):
    def seen(self, agent_id: str, nonce: str, now: float) -> bool:
        """Has this vote already cleared a quorum?"""

    def consume(self, entries: list[Entry], now: float) -> bool:
        """Record every vote as used, atomically. False if any was used."""


class MemoryNonceLedger:
    """Per-process ledger: the default when no shared store is configured."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._used: dict[tuple[str, str], float] = {}

    def _prune(self, now: float) -> None:
        cutoff = now - RETENTION_GRACE
        for key in [k for k, expires in self._used.items() if expires <= cutoff]:
            del self._used[key]

    def seen(self, agent_id: str, nonce: str, now: float) -> bool:
        with self._lock:
            self._prune(now)
            return (agent_id, nonce) in self._used

    def consume(self, entries: list[Entry], now: float) -> bool:
        with self._lock:
            self._prune(now)
            if any((agent, nonce) in self._used for agent, nonce, _ in entries):
                return False
            for agent, nonce, expires in entries:
                self._used[(agent, nonce)] = expires
            return True

    def health(self) -> str | None:
        return None


_SQLITE_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS used_votes ("
    " agent_id TEXT NOT NULL,"
    " nonce TEXT NOT NULL,"
    " expires_at REAL NOT NULL,"
    " PRIMARY KEY (agent_id, nonce))"
)


class SqliteNonceLedger:
    """Ledger shared by every process that opens the same file."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._lock = threading.Lock()
        try:
            self._db = sqlite3.connect(
                self.path, timeout=10.0, isolation_level=None, check_same_thread=False
            )
        except sqlite3.Error as exc:
            raise LedgerUnavailable(f"cannot open {self.path}: {exc}") from exc
        try:
            self._enable_wal()
            self._db.execute(_SQLITE_SCHEMA)
            # Prove the file can be written NOW. A read-only file opens and
            # answers reads; without this it would start "healthy" and then
            # fail every quorum.
            self._db.execute("BEGIN IMMEDIATE")
            self._db.execute("ROLLBACK")
        except sqlite3.Error as exc:
            self._db.close()
            raise LedgerUnavailable(
                f"quorum ledger {self.path} is not usable: {exc}"
            ) from exc
        except BaseException:
            self._db.close()
            raise

    def _enable_wal(self) -> None:
        # Switching journal mode can return SQLITE_BUSY immediately despite
        # the connection busy timeout when fresh replicas start together.
        # This retry is only for initialization, never vote consumption.
        deadline = time.monotonic() + 10.0
        while True:
            try:
                self._db.execute("PRAGMA journal_mode=WAL")
                return
            except sqlite3.OperationalError as exc:
                if (
                    getattr(exc, "sqlite_errorcode", None) != sqlite3.SQLITE_BUSY
                    or time.monotonic() >= deadline
                ):
                    raise
                time.sleep(0.01)

    def seen(self, agent_id: str, nonce: str, now: float) -> bool:
        with self._lock:
            try:
                row = self._db.execute(
                    "SELECT 1 FROM used_votes"
                    " WHERE agent_id = ? AND nonce = ? AND expires_at > ?",
                    (agent_id, nonce, now - RETENTION_GRACE),
                ).fetchone()
            except sqlite3.Error as exc:
                raise LedgerUnavailable(f"quorum ledger read failed: {exc}") from exc
        return row is not None

    def consume(self, entries: list[Entry], now: float) -> bool:
        with self._lock:
            try:
                # IMMEDIATE takes the write lock up front, so two replicas
                # consuming the same votes are serialized, not interleaved.
                self._db.execute("BEGIN IMMEDIATE")
            except sqlite3.Error as exc:
                raise LedgerUnavailable(f"quorum ledger write failed: {exc}") from exc
            try:
                self._db.execute(
                    "DELETE FROM used_votes WHERE expires_at <= ?",
                    (now - RETENTION_GRACE,),
                )
                self._db.executemany(
                    "INSERT INTO used_votes (agent_id, nonce, expires_at)"
                    " VALUES (?, ?, ?)",
                    entries,
                )
                self._db.execute("COMMIT")
            except sqlite3.IntegrityError:
                self._db.execute("ROLLBACK")
                return False
            except sqlite3.Error as exc:
                self._rollback_quietly()
                raise LedgerUnavailable(f"quorum ledger write failed: {exc}") from exc
            except BaseException:
                self._rollback_quietly()
                raise
            return True

    def _rollback_quietly(self) -> None:
        try:
            self._db.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    def health(self) -> str | None:
        """None when the ledger can be written right now, else the reason."""
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                self._db.execute("SELECT 1 FROM used_votes LIMIT 1").fetchone()
                self._db.execute("ROLLBACK")
            except sqlite3.Error as exc:
                self._rollback_quietly()
                return f"{type(exc).__name__}: {exc}"
        return None

    def close(self) -> None:
        with self._lock:
            self._db.close()


_PG_SCHEMA = """
CREATE TABLE IF NOT EXISTS used_votes (
    agent_id   TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    expires_at DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (agent_id, nonce)
);
"""


class PostgresNonceLedger:
    """The same ledger in PostgreSQL, for replicas on separate hosts.

    ``pool`` is the runtime's psycopg connection pool. A second replica
    inserting the same (voter, nonce) waits on the first one's transaction
    and then fails the primary key, so exactly one of them clears.
    """

    def __init__(self, pool: Any) -> None:
        self._pool = pool
        try:
            with pool.connection() as conn:
                conn.execute(_PG_SCHEMA)
        except Exception as exc:
            raise LedgerUnavailable(f"quorum ledger (PostgreSQL): {exc}") from exc

    def seen(self, agent_id: str, nonce: str, now: float) -> bool:
        try:
            with self._pool.connection() as conn:
                row = conn.execute(
                    "SELECT 1 FROM used_votes"
                    " WHERE agent_id = %s AND nonce = %s AND expires_at > %s",
                    (agent_id, nonce, now - RETENTION_GRACE),
                ).fetchone()
        except Exception as exc:
            raise LedgerUnavailable(f"quorum ledger read failed: {exc}") from exc
        return row is not None

    def consume(self, entries: list[Entry], now: float) -> bool:
        from psycopg import errors

        try:
            with self._pool.connection() as conn:
                with conn.transaction():
                    conn.execute(
                        "DELETE FROM used_votes WHERE expires_at <= %s",
                        (now - RETENTION_GRACE,),
                    )
                    # Fixed order, so two replicas spending overlapping
                    # quorums queue on the same row instead of deadlocking.
                    for agent, nonce, expires in sorted(entries):
                        conn.execute(
                            "INSERT INTO used_votes (agent_id, nonce, expires_at)"
                            " VALUES (%s, %s, %s)",
                            (agent, nonce, expires),
                        )
        except errors.UniqueViolation:
            return False
        except Exception as exc:
            raise LedgerUnavailable(f"quorum ledger write failed: {exc}") from exc
        return True

    def health(self) -> str | None:
        try:
            with self._pool.connection() as conn:
                conn.execute("SELECT 1 FROM used_votes LIMIT 1").fetchone()
        except Exception as exc:
            return f"{type(exc).__name__}: {exc}"
        return None
