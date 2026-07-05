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
    record_hash TEXT NOT NULL,
    body        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_agent ON records(agent_id);
CREATE INDEX IF NOT EXISTS idx_capability ON records(capability);
CREATE INDEX IF NOT EXISTS idx_decision ON records(decision);
"""


class SQLiteDecisionStore:
    def __init__(self, path: Union[str, Path]) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
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
            " decision_ref, record_hash, body) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                kind,
                d.get("decision_id") or d.get("event_id"),
                d["agent_id"],
                d.get("capability"),
                d.get("decision"),
                d.get("decision_ref"),
                d["record_hash"],
                body,
            ),
        )
        self._conn.commit()

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
        self._conn.close()
