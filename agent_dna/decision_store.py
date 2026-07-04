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
from pathlib import Path
from typing import Iterator, List, Union

from .decision_graph import DecisionGraph
from .decision_record import DecisionRecord


class DecisionStore:
    def __init__(self, path: Union[str, Path]) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # ---- write --------------------------------------------------------

    def append(self, record: DecisionRecord) -> None:
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

    def _iter_dicts(self) -> Iterator[dict]:
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
                    raise ValueError(
                        f"{self.path}:{lineno}: corrupt JSONL line"
                    ) from e

    def load(self) -> List[DecisionRecord]:
        records: List[DecisionRecord] = []
        for d in self._iter_dicts():
            record_hash = d.pop("record_hash")
            rec = DecisionRecord(**d)
            rec.record_hash = record_hash
            records.append(rec)
        return records

    def load_graph(self) -> DecisionGraph:
        """Rebuild the full DecisionGraph from disk. DecisionGraph.add
        verifies every record, so a tampered file fails loudly here."""
        g = DecisionGraph()
        for rec in self.load():
            g.add(rec)
        return g
