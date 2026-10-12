"""Append-only, hash-chained receipt log for one agent run.

Each entry records what PrivateVault decided and what happened next: the
decision id and record hash, the verdict and its trigger, the approval
digest, the permit id, the dispatch outcome, and the receiver's receipt
digest and sequence. It is the agent operator's own trail; the authoritative
records are the sealed decisions in PrivateVault and the receiver's receipts.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _entry_hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


class ReceiptLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> tuple[int, str]:
        entries = self.entries()
        if not entries:
            return 0, GENESIS
        return int(entries[-1]["seq"]), str(entries[-1]["entry_hash"])

    def record(self, entry: dict[str, Any]) -> dict[str, Any]:
        seq, prev = self._last_hash()
        full = {
            **entry,
            "seq": seq + 1,
            "at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "prev_hash": prev,
        }
        full["entry_hash"] = _entry_hash(full)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(full, sort_keys=True, default=str) + "\n")
        return full

    def entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [
            json.loads(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def verify(self) -> bool:
        prev = GENESIS
        for index, entry in enumerate(self.entries(), start=1):
            if entry.get("seq") != index or entry.get("prev_hash") != prev:
                return False
            if entry.get("entry_hash") != _entry_hash(entry):
                return False
            prev = str(entry["entry_hash"])
        return True

    def summary(self) -> str:
        lines = []
        for e in self.entries():
            lines.append(
                f"#{e['seq']:<2} {e.get('tool', '?'):<28} "
                f"{e.get('decision', '?'):<16} via {e.get('triggered_by', '?'):<13} "
                f"permit={str(e.get('permit_id') or '-')[:14]:<14} "
                f"dispatch={e.get('dispatch_outcome') or '-':<15} "
                f"receiver_seq={e.get('receiver_sequence') if e.get('receiver_sequence') is not None else '-'}"
            )
        return "\n".join(lines)
