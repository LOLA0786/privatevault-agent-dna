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
-- Audit set 4: at most ONE execution event per decision, enforced by
-- the database across processes -- the in-memory graph's duplicate
-- check cannot see another writer. NOTE: creating this index on a
-- pre-existing store already containing duplicate executions fails
-- loudly at open; a store violating the invariant should refuse to
-- start, not paper over it.
CREATE UNIQUE INDEX IF NOT EXISTS idx_execution_per_decision
    ON records(decision_ref)
    WHERE kind = 'execution';
-- Signature envelopes persisted in the SAME transaction as their
-- record: a signed decision without its envelope (or an envelope for
-- a record that was never committed) is unrepresentable.
CREATE TABLE IF NOT EXISTS envelopes (
    record_hash TEXT PRIMARY KEY,
    agent_id    TEXT NOT NULL,
    envelope    TEXT NOT NULL
);
"""


class SQLiteDecisionStore:
    def __init__(self, path: str | Path) -> None:
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

    SUPPORTS_ENVELOPES = True

    @staticmethod
    def _integrity_detail(exc: sqlite3.IntegrityError) -> str:
        msg = str(exc)
        if "records.decision_ref" in msg:
            return "duplicate execution event for this decision"
        if "records.record_id" in msg:
            return "duplicate record id"
        return msg

    def append(self, record, envelope: dict | None = None) -> None:
        """Persist one record -- and, when provided, its signature
        envelope -- in a SINGLE transaction (audit set 4). The failure
        windows 'record committed, envelope only in memory' and
        'envelope written, record insert failed' are closed by the
        transaction boundary, not by call ordering."""
        if not record.verify():
            raise ValueError("record is unsealed or tampered; refusing to persist")
        d = record.to_dict()
        body = json.dumps(d, sort_keys=True, separators=(",", ":"))
        kind = d.get("kind", "decision")
        env_body = (
            json.dumps(envelope, sort_keys=True, separators=(",", ":"))
            if envelope is not None
            else None
        )
        conn = self._conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
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
            if env_body is not None:
                conn.execute(
                    "INSERT INTO envelopes (record_hash, agent_id, envelope) "
                    "VALUES (?, ?, ?)",
                    (d["record_hash"], d["agent_id"], env_body),
                )
            conn.commit()
        except sqlite3.IntegrityError as e:
            conn.rollback()
            raise ValueError(self._integrity_detail(e)) from e
        except Exception:
            conn.rollback()
            raise

    def get_envelope(self, record_hash: str) -> dict | None:
        row = self._conn.execute(
            "SELECT envelope FROM envelopes WHERE record_hash = ?",
            (record_hash,),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def iter_decisions(self, since_ts: float | None = None):
        """Read-only iteration over sealed decision bodies, oldest
        first. For analysis tools (policy mining) that must observe the
        audit trail without ever mutating it."""
        for (body,) in self._conn.execute(
            "SELECT body FROM records WHERE kind = 'decision' ORDER BY seq"
        ):
            rec = json.loads(body)
            if since_ts is None or rec.get("timestamp", 0.0) >= since_ts:
                yield rec

    def iter_executions(self):
        """Read-only iteration over execution events."""
        for (body,) in self._conn.execute(
            "SELECT body FROM records WHERE kind = 'execution' ORDER BY seq"
        ):
            yield json.loads(body)

    def load_envelopes(self) -> dict:
        return {
            h: json.loads(env)
            for h, env in self._conn.execute(
                "SELECT record_hash, envelope FROM envelopes"
            )
        }

    def get_decision(self, decision_id: str) -> dict | None:
        """Authoritative decision lookup for multi-writer mode, where
        the in-memory graph is deliberately not populated (audit: the
        store, not the graph, is the source of truth there)."""
        row = self._conn.execute(
            "SELECT body FROM records WHERE record_id = ? AND kind = 'decision'",
            (decision_id,),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def append_atomic(self, record, envelope: dict | None = None) -> bool:
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
            raise ValueError("record is unsealed or tampered; refusing to persist")
        d = record.to_dict()
        if d.get("kind", "decision") != "decision":
            raise ValueError(
                "append_atomic is for decision records only -- "
                "execution events use append() (anchored, not chained)"
            )
        body = json.dumps(d, sort_keys=True, separators=(",", ":"))

        env_body = (
            json.dumps(envelope, sort_keys=True, separators=(",", ":"))
            if envelope is not None
            else None
        )
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
            if env_body is not None:
                conn.execute(
                    "INSERT INTO envelopes (record_hash, agent_id, envelope) "
                    "VALUES (?, ?, ?)",
                    (d["record_hash"], d["agent_id"], env_body),
                )
            conn.commit()
            return True
        except sqlite3.IntegrityError as e:
            conn.rollback()
            # Audit set 4: ONLY a chain-head race (the (agent_id,
            # prev_hash) unique index) is a retryable lost race. Every
            # other integrity failure -- duplicate decision_id,
            # duplicate execution, duplicate envelope -- is corruption
            # and must surface, not be silently retried as if another
            # writer had legitimately advanced the chain.
            if "records.agent_id, records.prev_hash" in str(e):
                return False
            raise ValueError(self._integrity_detail(e)) from e
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

    def _rows(self) -> list[str]:
        cur = self._conn.execute("SELECT body FROM records ORDER BY seq")
        return [r[0] for r in cur.fetchall()]

    def load(self) -> list[DecisionRecord | ExecutionEvent]:
        out: list[DecisionRecord | ExecutionEvent] = []
        for body in self._rows():
            d = json.loads(body)
            record_hash = d.pop("record_hash")
            kind = d.pop("kind", "decision")
            protocol_version = d.pop("protocol_version", None)
            if kind == "execution":
                record: DecisionRecord | ExecutionEvent = ExecutionEvent(**d)
            else:
                if protocol_version is None:
                    raise ValueError(
                        "decision record missing required protocol_version"
                    )
                record = DecisionRecord(
                    protocol_version=protocol_version,
                    **d,
                )
            record.record_hash = record_hash
            out.append(record)
        return out

    def load_graph(self) -> DecisionGraph:
        g = DecisionGraph()
        for rec in self.load():
            if isinstance(rec, ExecutionEvent):
                g.add_execution(rec)
            else:
                g.add(rec)
        return g

    # ---- audit export -----------------------------------------------------

    def export_jsonl(self, path: str | Path) -> Path:
        """Emit the canonical JSONL audit file — byte-identical record
        serialization — for the independent verifier."""
        path = Path(path)
        path.write_text("\n".join(self._rows()) + "\n")
        return path

    def export_envelopes_jsonl(self, path: str | Path) -> Path:
        """Export detached signature envelopes in deterministic order."""
        path = Path(path)

        # Keep orphaned envelopes visible so an external verifier can
        # reject them instead of silently excluding corrupted state.
        rows = self._conn.execute(
            "SELECT e.envelope FROM envelopes AS e "
            "LEFT JOIN records AS r ON r.record_hash = e.record_hash "
            "ORDER BY r.seq IS NULL, r.seq, e.record_hash"
        )

        path.write_text(
            "".join(f"{row[0]}\n" for row in rows),
            encoding="utf-8",
        )
        return path

    def ping(self) -> bool:
        """Return True when the WAL store accepts a trivial query."""
        self._conn.execute("SELECT 1").fetchone()
        return True

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None
