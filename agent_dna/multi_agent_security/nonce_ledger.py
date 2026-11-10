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

Limit: replicas must share the file, so this covers replicas on one host or
on a shared volume. Replicas on separate hosts with only PostgreSQL in
common need the same table there; that is not shipped.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Protocol

Entry = tuple[str, str, float]  # (agent_id, nonce, expires_at)


class NonceLedger(Protocol):
    def seen(self, agent_id: str, nonce: str, now: float) -> bool:
        """Has this vote already cleared a quorum (and not yet expired)?"""

    def consume(self, entries: list[Entry], now: float) -> bool:
        """Record every vote as used, atomically. False if any was used."""


class MemoryNonceLedger:
    """Per-process ledger: the default when no shared file is configured."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._used: dict[tuple[str, str], float] = {}

    def _prune(self, now: float) -> None:
        for key in [k for k, expires in self._used.items() if expires <= now]:
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


class SqliteNonceLedger:
    """Ledger shared by every process that opens the same file."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(
            self.path, timeout=10.0, isolation_level=None, check_same_thread=False
        )
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS used_votes ("
            " agent_id TEXT NOT NULL,"
            " nonce TEXT NOT NULL,"
            " expires_at REAL NOT NULL,"
            " PRIMARY KEY (agent_id, nonce))"
        )

    def seen(self, agent_id: str, nonce: str, now: float) -> bool:
        with self._lock:
            row = self._db.execute(
                "SELECT 1 FROM used_votes"
                " WHERE agent_id = ? AND nonce = ? AND expires_at > ?",
                (agent_id, nonce, now),
            ).fetchone()
        return row is not None

    def consume(self, entries: list[Entry], now: float) -> bool:
        with self._lock:
            # IMMEDIATE takes the write lock up front, so two replicas
            # consuming the same votes are serialized, not interleaved.
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._db.execute("DELETE FROM used_votes WHERE expires_at <= ?", (now,))
                self._db.executemany(
                    "INSERT INTO used_votes (agent_id, nonce, expires_at)"
                    " VALUES (?, ?, ?)",
                    entries,
                )
            except sqlite3.IntegrityError:
                self._db.execute("ROLLBACK")
                return False
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            self._db.execute("COMMIT")
            return True

    def close(self) -> None:
        with self._lock:
            self._db.close()
