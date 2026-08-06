"""
DecisionStore — append-only JSONL persistence for DecisionRecords.

One JSON object per line, in causal (append) order. The file is the
audit artifact: it can be verified WITHOUT this package by
tools/verify_records.py (stdlib only) — that independence is the
point.

No update, no delete. Tampering means editing the file, and editing
the file breaks the hash chain.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .decision_graph import DecisionGraph
from .decision_record import DecisionRecord
from .execution_record import ExecutionEvent


class DecisionStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # ---- write --------------------------------------------------------

    def append(self, record) -> None:
        """Accepts any sealed record with verify()/to_dict()
        (DecisionRecord or ExecutionEvent)."""
        if not record.verify():
            raise ValueError(
                f"record {record.decision_id} is unsealed or tampered; "
                "refusing to persist"
            )
        line = json.dumps(
            record.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        )
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()

    # ---- read ---------------------------------------------------------

    def _iter_dicts(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError as e:
                    raise ValueError(f"{self.path}:{lineno}: corrupt JSONL line") from e

    def load(self) -> list[DecisionRecord | ExecutionEvent]:
        records: list[DecisionRecord | ExecutionEvent] = []
        for d in self._iter_dicts():
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
            records.append(record)
        return records

    def load_graph(self) -> DecisionGraph:
        """Rebuild the full DecisionGraph from disk. add/add_execution
        verify every record, so a tampered file fails loudly here."""
        g = DecisionGraph()
        for rec in self.load():
            if isinstance(rec, ExecutionEvent):
                g.add_execution(rec)
            else:
                g.add(rec)
        return g
