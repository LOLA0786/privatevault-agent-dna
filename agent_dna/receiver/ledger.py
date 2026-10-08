"""Receiver-owned durable ledger: single-use consumption plus the receipt chain.

This ledger belongs to the receiving system's operator and is separate from
any ledger the agent-side sidecar keeps. Even if every agent-side control is
skipped, a permit can be admitted here at most once per receiver.

One SQLite transaction (``BEGIN IMMEDIATE``) does both things atomically:

1. optionally claims ``(organisation_id, execution_authorization_id)`` under a
   UNIQUE key, and
2. appends the next receipt, linked to the previous receipt digest.

A claim that loses the race produces a REFUSED receipt in the same
transaction. Receipt sequence and linkage are allocated inside the lock, so
concurrent workers and separate processes sharing the file cannot fork the
chain. Multi-host deployments need a store with the same exclusive-claim
guarantee; this module does not claim one.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterator, Mapping
from contextlib import closing
from pathlib import Path
from typing import Any

from agent_dna.authority_v01 import sha256_digest, strict_json_loads
from agent_dna.receiver.receipts import GENESIS_DIGEST

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS receiver_consume (
        organisation_id TEXT NOT NULL,
        execution_authorization_id TEXT NOT NULL,
        consumed_at TEXT NOT NULL,
        receipt_sequence INTEGER NOT NULL,
        PRIMARY KEY (organisation_id, execution_authorization_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS receiver_receipts (
        sequence INTEGER PRIMARY KEY,
        receipt_digest TEXT NOT NULL UNIQUE,
        receipt_json TEXT NOT NULL
    )
    """,
)

# make_receipt(claimed, sequence, previous_digest) -> signed receipt.
# ``claimed`` is None when no claim was requested, else True/False.
ReceiptFactory = Callable[[bool | None, int, str], Mapping[str, Any]]


class ReceiverLedger:
    """SQLite-backed consume ledger and receipt chain for one receiver."""

    def __init__(self, path: str | Path, *, timeout_s: float = 5.0) -> None:
        self.path = str(path)
        self.timeout_s = timeout_s
        with closing(self._connect()) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            for statement in _SCHEMA:
                conn.execute(statement)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=self.timeout_s, isolation_level=None)
        conn.execute(f"PRAGMA busy_timeout={int(self.timeout_s * 1000)}")
        return conn

    def record(
        self,
        *,
        claim: tuple[str, str, str] | None,
        make_receipt: ReceiptFactory,
    ) -> tuple[bool | None, dict[str, Any]]:
        """Atomically (claim?) and append one receipt.

        ``claim`` is ``(organisation_id, execution_authorization_id, consumed_at)``.
        Returns ``(claimed, receipt)``. Any exception rolls back both.
        """

        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                claimed: bool | None = None
                row = conn.execute(
                    "SELECT sequence, receipt_digest FROM receiver_receipts "
                    "ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                sequence = 1 if row is None else int(row[0]) + 1
                previous = GENESIS_DIGEST if row is None else str(row[1])
                if claim is not None:
                    organisation_id, ea_id, consumed_at = claim
                    try:
                        conn.execute(
                            "INSERT INTO receiver_consume (organisation_id, "
                            "execution_authorization_id, consumed_at, "
                            "receipt_sequence) VALUES (?, ?, ?, ?)",
                            (organisation_id, ea_id, consumed_at, sequence),
                        )
                        claimed = True
                    except sqlite3.IntegrityError:
                        claimed = False
                receipt = dict(make_receipt(claimed, sequence, previous))
                if (
                    receipt.get("sequence") != sequence
                    or receipt.get("previous_receipt_digest") != previous
                ):
                    raise RuntimeError("receipt factory ignored allocated linkage")
                digest = sha256_digest(receipt)
                conn.execute(
                    "INSERT INTO receiver_receipts (sequence, receipt_digest, "
                    "receipt_json) VALUES (?, ?, ?)",
                    (sequence, digest, json.dumps(receipt, sort_keys=True)),
                )
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return claimed, receipt

    def is_consumed(
        self, organisation_id: str, execution_authorization_id: str
    ) -> bool:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT 1 FROM receiver_consume WHERE organisation_id = ? AND "
                "execution_authorization_id = ?",
                (organisation_id, execution_authorization_id),
            ).fetchone()
        return row is not None

    def iter_receipts(self) -> Iterator[dict[str, Any]]:
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT receipt_json FROM receiver_receipts ORDER BY sequence ASC"
            ).fetchall()
        for (raw,) in rows:
            value = strict_json_loads(raw)
            if not isinstance(value, dict):
                raise RuntimeError("stored receipt is not a JSON object")
            yield value
