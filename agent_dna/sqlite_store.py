"""
SQLiteDecisionStore — concurrent-safe persistence for decision records.

Same append/load/load_graph contract as DecisionStore (JSONL), so the
recorder doesn't know which one it has. WAL mode: concurrent readers
during writes, single-writer append semantics enforced by SQLite.

The full canonical JSON of every record is stored verbatim in the
`body` column — the database is an index over the audit artifact, not
a replacement for it. `export_jsonl()` reproduces the exact file the
independent verifier consumes; the DB never becomes a second source
of truth with its own serialization.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import List, Union

from .decision_graph import DecisionGraph
from .decision_record import DecisionRecord
from .execution_record import ExecutionEvent

_SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,
    record_id   TEXT NOT NULL UNIQUE,
    agent_id    TEXT NOT NULL,
    capability  TEXT,
    decision    TEXT,
    decision_ref TEXT,
    prev_hash   TEXT,
    record_hash TEXT NOT NULL,
    body        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent ON records(agent_id);
CREATE INDEX IF NOT EXISTS idx_capability ON records(capability);
CREATE INDEX IF NOT EXISTS idx_decision ON records(decision);
-- Multi-writer safety: at most one decision record per (agent, parent
-- hash). If two processes race to extend the same agent's chain from
-- the same prev_hash, the database itself rejects the second insert
-- -- atomically, not via application-level timing. Execution events
-- are excluded (kind != 'decision') since they anchor to a decision,
-- not to each other.
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_prevhash
    ON records(agent_id, prev_hash)
    WHERE kind = 'decision';
"""


class SQLiteDecisionStore:
    def __init__(self, path: Union[str, Path]) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        #
        # Thread-local connections: sqlite3 connections are NOT
        # thread-safe even with check_same_thread=False — concurrent
        # use of one connection corrupts cursor state (empty tuples
        # from fetchall(), the exact race caught by the pinning
        # test). Each thread gets its own connection to the same WAL
        # database; WAL provides the actual concurrency model.
        #
        self._local = threading.local()
        self._migrate_add_prev_hash_column()
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    @property
    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn = conn
        return conn

    def _migrate_add_prev_hash_column(self) -> None:
        """Add prev_hash to a pre-existing records table that predates
        this column, so the unique index in _SCHEMA can be created.
        No-op if the table doesn't exist yet or already has the
        column."""
        cur = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='records'"
        )
        if cur.fetchone() is None:
            return  # fresh DB, _SCHEMA below creates it correctly
        cols = [r[1] for r in self._conn.execute("PRAGMA table_info(records)")]
        if "prev_hash" not in cols:
            self._conn.execute("ALTER TABLE records ADD COLUMN prev_hash TEXT")
            self._conn.commit()

    # ---- write ----------------------------------------------------------

    def append(self, record) -> None:
        if not record.verify():
            raise ValueError(
                f"record is unsealed or tampered; refusing to persist"
            )
        d = record.to_dict()
        body = json.dumps(d, sort_keys=True, separators=(",", ":"))
        kind = d.get("kind", "decision")
        self._conn.execute(
            "INSERT INTO records "
            "(kind, record_id, agent_id, capability, decision, "
            " decision_ref, prev_hash, record_hash, body) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                kind,
                d.get("decision_id") or d.get("event_id"),
                d["agent_id"],
                d.get("capability"),
                d.get("decision"),
                d.get("decision_ref"),
                d.get("prev_hash"),
                d["record_hash"],
                body,
            ),
        )
        self._conn.commit()

    def append_atomic(self, record) -> bool:
        """Multi-writer-safe append for decision records only. Returns
        True on success, False if another writer already claimed this
        (agent_id, prev_hash) pair -- i.e. someone else extended this
        agent's chain from the same parent first. On False, the caller
        MUST re-read the chain head (get_chain_head) and retry with a
        fresh prev_hash; do not blindly retry the same record.

        Atomicity is enforced by the database's UNIQUE(agent_id,
        prev_hash) constraint (see _SCHEMA), not by application-level
        timing -- two processes racing to insert against the same
        prev_hash will have exactly one succeed, guaranteed by SQLite
        itself.

        Uses its OWN short-lived connection, never self._conn. A
        shared connection object cannot safely have concurrent
        threads each issuing their own BEGIN IMMEDIATE against it --
        Python's sqlite3 module manages an implicit transaction per
        connection, and concurrent explicit transaction control on
        one connection object corrupts that state ('cannot start a
        transaction within a transaction'). WAL mode makes multiple
        connections to the same FILE safe and concurrent; it does not
        make one shared connection OBJECT safe for concurrent
        transaction control."""
        if not record.verify():
            raise ValueError(
                "record is unsealed or tampered; refusing to persist"
            )
        d = record.to_dict()
        if d.get("kind", "decision") != "decision":
            raise ValueError(
                "append_atomic is for decision records only -- "
                "execution events use append() (anchored, not chained)"
            )
        body = json.dumps(d, sort_keys=True, separators=(",", ":"))

        conn = sqlite3.connect(self.path, timeout=10.0)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "INSERT INTO records "
                "(kind, record_id, agent_id, capability, decision, "
                " decision_ref, prev_hash, record_hash, body) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    d["kind"],
                    d.get("decision_id"),
                    d["agent_id"],
                    d.get("capability"),
                    d.get("decision"),
                    d.get("decision_ref"),
                    d.get("prev_hash"),
                    d["record_hash"],
                    body,
                ),
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            conn.rollback()
            return False
        finally:
            conn.close()

    def get_chain_head(self, agent_id: str):
        """Live read of an agent's current chain head directly from
        the store -- bypasses any in-memory cache. Returns
        (last_decision_id, last_record_hash) or (None, GENESIS_HASH)
        if the agent has no decision records yet.

        Uses its own short-lived connection -- see append_atomic's
        docstring for why this cannot safely share self._conn across
        threads."""
        from .decision_record import GENESIS_HASH

        conn = sqlite3.connect(self.path, timeout=10.0)
        try:
            cur = conn.execute(
                "SELECT record_id, record_hash FROM records "
                "WHERE agent_id = ? AND kind = 'decision' "
                "ORDER BY seq DESC LIMIT 1",
                (agent_id,),
            )
            row = cur.fetchone()
            if row is None:
                return None, GENESIS_HASH
            return row[0], row[1]
        finally:
            conn.close()

    # ---- read -----------------------------------------------------------

    def _rows(self) -> List[str]:
        cur = self._conn.execute("SELECT body FROM records ORDER BY seq")
        return [r[0] for r in cur.fetchall()]

    def load(self) -> List:
        out: List = []
        for body in self._rows():
            d = json.loads(body)
            record_hash = d.pop("record_hash")
            kind = d.pop("kind", "decision")
            d.pop("protocol_version", None)   # init=False, restored by dataclass
            rec = ExecutionEvent(**d) if kind == "execution" else DecisionRecord(**d)
            rec.record_hash = record_hash
            out.append(rec)
        return out

    def load_graph(self) -> DecisionGraph:
        g = DecisionGraph()
        for rec in self.load():
            if rec.kind == "execution":
                g.add_execution(rec)
            else:
                g.add(rec)
        return g

    # ---- audit export -----------------------------------------------------

    def export_jsonl(self, path: Union[str, Path]) -> Path:
        """Emit the canonical JSONL audit file — byte-identical record
        serialization — for the independent verifier."""
        path = Path(path)
        path.write_text("\n".join(self._rows()) + "\n")
        return path

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None
