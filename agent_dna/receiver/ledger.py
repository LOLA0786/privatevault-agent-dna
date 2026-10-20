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

With business transaction keys (ADR 0030) the same transaction also claims
``(organisation_id, operation, transaction_key)``: a key held by an earlier
permit, in any state but NOT_EXECUTED, refuses the request without
consuming its permit. Outcomes and reconciliations update the claim and
append to ``receiver_transaction_events``.
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
from agent_dna.receiver.transactions import (
    CLAIMED,
    NOT_EXECUTED,
    OPEN_STATES,
    RESOLUTIONS,
    classify_upstream,
)

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
    """
    CREATE TABLE IF NOT EXISTS receiver_transactions (
        organisation_id TEXT NOT NULL,
        operation TEXT NOT NULL,
        transaction_key TEXT NOT NULL,
        state TEXT NOT NULL,
        execution_authorization_id TEXT NOT NULL,
        claimed_at TEXT NOT NULL,
        receipt_sequence INTEGER NOT NULL,
        updated_at TEXT NOT NULL,
        upstream_status INTEGER,
        PRIMARY KEY (organisation_id, operation, transaction_key)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_receiver_transactions_permit
        ON receiver_transactions (organisation_id, execution_authorization_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS receiver_transaction_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        organisation_id TEXT NOT NULL,
        operation TEXT NOT NULL,
        transaction_key TEXT NOT NULL,
        at TEXT NOT NULL,
        from_state TEXT,
        to_state TEXT NOT NULL,
        execution_authorization_id TEXT,
        upstream_status INTEGER,
        actor TEXT NOT NULL,
        note TEXT
    )
    """,
)

# Result of a claim request, passed to the receipt factory.
CLAIM_ADMITTED = True
CLAIM_PERMIT_CONSUMED = False
CLAIM_DUPLICATE_TRANSACTION = "duplicate_transaction"

# make_receipt(claimed, sequence, previous_digest) -> signed receipt.
# ``claimed`` is None when no claim was requested; True when the permit (and
# its transaction key, if any) was claimed; False when the permit was
# already consumed; CLAIM_DUPLICATE_TRANSACTION when another permit holds
# the transaction key.
ClaimResult = bool | str | None
ReceiptFactory = Callable[[ClaimResult, int, str], Mapping[str, Any]]


class TransactionStateError(ValueError):
    """A reconciliation that the claim's current state does not allow."""


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
        transaction: tuple[str, str] | None = None,
    ) -> tuple[ClaimResult, dict[str, Any]]:
        """Atomically (claim?) and append one receipt.

        ``claim`` is ``(organisation_id, execution_authorization_id, consumed_at)``.
        ``transaction`` is ``(operation, transaction_key)``, claimed for the
        same organisation before the permit; a key already held refuses
        without consuming the permit. Returns ``(claimed, receipt)``. Any
        exception rolls back everything.
        """

        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                claimed: ClaimResult = None
                row = conn.execute(
                    "SELECT sequence, receipt_digest FROM receiver_receipts "
                    "ORDER BY sequence DESC LIMIT 1"
                ).fetchone()
                sequence = 1 if row is None else int(row[0]) + 1
                previous = GENESIS_DIGEST if row is None else str(row[1])
                if claim is not None:
                    organisation_id, ea_id, consumed_at = claim
                    held = None
                    if transaction is not None:
                        held = conn.execute(
                            "SELECT state FROM receiver_transactions WHERE "
                            "organisation_id = ? AND operation = ? AND "
                            "transaction_key = ?",
                            (organisation_id, *transaction),
                        ).fetchone()
                    if held is not None and held[0] != NOT_EXECUTED:
                        claimed = CLAIM_DUPLICATE_TRANSACTION
                    else:
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
                    if claimed is True and transaction is not None:
                        conn.execute(
                            "INSERT INTO receiver_transactions (organisation_id, "
                            "operation, transaction_key, state, "
                            "execution_authorization_id, claimed_at, "
                            "receipt_sequence, updated_at, upstream_status) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL) "
                            "ON CONFLICT (organisation_id, operation, "
                            "transaction_key) DO UPDATE SET state = excluded.state, "
                            "execution_authorization_id = "
                            "excluded.execution_authorization_id, "
                            "claimed_at = excluded.claimed_at, "
                            "receipt_sequence = excluded.receipt_sequence, "
                            "updated_at = excluded.updated_at, upstream_status = NULL",
                            (
                                organisation_id,
                                *transaction,
                                CLAIMED,
                                ea_id,
                                consumed_at,
                                sequence,
                                consumed_at,
                            ),
                        )
                        self._event(
                            conn,
                            organisation_id,
                            transaction,
                            at=consumed_at,
                            from_state=None if held is None else str(held[0]),
                            to_state=CLAIMED,
                            ea_id=ea_id,
                            actor="gate",
                        )
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

    @staticmethod
    def _event(
        conn: sqlite3.Connection,
        organisation_id: str,
        transaction: tuple[str, str],
        *,
        at: str,
        from_state: str | None,
        to_state: str,
        ea_id: str | None,
        actor: str,
        upstream_status: int | None = None,
        note: str | None = None,
    ) -> None:
        conn.execute(
            "INSERT INTO receiver_transaction_events (organisation_id, operation, "
            "transaction_key, at, from_state, to_state, execution_authorization_id, "
            "upstream_status, actor, note) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                organisation_id,
                *transaction,
                at,
                from_state,
                to_state,
                ea_id,
                upstream_status,
                actor,
                note,
            ),
        )

    def record_outcome(
        self,
        organisation_id: str,
        execution_authorization_id: str,
        upstream_status: int | None,
        *,
        at: str,
    ) -> str | None:
        """Record the upstream's answer for the permit's transaction claim.

        Moves a CLAIMED claim to EXECUTED, NOT_EXECUTED or INDETERMINATE
        (``classify_upstream``). Returns the new state, or None when the
        permit claimed no transaction key or its claim already left CLAIMED.
        """
        state = classify_upstream(upstream_status)
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT operation, transaction_key FROM receiver_transactions "
                    "WHERE organisation_id = ? AND execution_authorization_id = ? "
                    "AND state = ?",
                    (organisation_id, execution_authorization_id, CLAIMED),
                ).fetchone()
                if row is None:
                    conn.execute("COMMIT")
                    return None
                transaction = (str(row[0]), str(row[1]))
                conn.execute(
                    "UPDATE receiver_transactions SET state = ?, updated_at = ?, "
                    "upstream_status = ? WHERE organisation_id = ? AND "
                    "operation = ? AND transaction_key = ?",
                    (state, at, upstream_status, organisation_id, *transaction),
                )
                self._event(
                    conn,
                    organisation_id,
                    transaction,
                    at=at,
                    from_state=CLAIMED,
                    to_state=state,
                    ea_id=execution_authorization_id,
                    actor="upstream",
                    upstream_status=upstream_status,
                )
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return state

    def resolve_transaction(
        self,
        organisation_id: str,
        operation: str,
        transaction_key: str,
        *,
        resolution: str,
        actor: str,
        note: str,
        at: str,
    ) -> str:
        """An operator's reconciliation of an open claim against the system
        of record: EXECUTED keeps the key refused for good, NOT_EXECUTED
        frees it for a new permit. Returns the previous state."""
        if resolution not in RESOLUTIONS:
            raise TransactionStateError(
                f"resolution must be one of {sorted(RESOLUTIONS)}"
            )
        if not actor.strip() or not note.strip():
            raise TransactionStateError("a reconciliation names who and why")
        transaction = (operation, transaction_key)
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT state, execution_authorization_id FROM "
                    "receiver_transactions WHERE organisation_id = ? AND "
                    "operation = ? AND transaction_key = ?",
                    (organisation_id, *transaction),
                ).fetchone()
                if row is None:
                    raise TransactionStateError("no claim for that transaction")
                previous = str(row[0])
                if previous not in OPEN_STATES:
                    raise TransactionStateError(
                        f"claim is {previous}; only {sorted(OPEN_STATES)} are reconciled"
                    )
                conn.execute(
                    "UPDATE receiver_transactions SET state = ?, updated_at = ? "
                    "WHERE organisation_id = ? AND operation = ? AND "
                    "transaction_key = ?",
                    (resolution, at, organisation_id, *transaction),
                )
                self._event(
                    conn,
                    organisation_id,
                    transaction,
                    at=at,
                    from_state=previous,
                    to_state=resolution,
                    ea_id=str(row[1]),
                    actor=actor,
                    note=note,
                )
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return previous

    def transactions(self, *, open_only: bool = False) -> list[dict[str, Any]]:
        """Transaction claims, oldest first; ``open_only``: CLAIMED and
        INDETERMINATE, the ones to reconcile."""
        sql = (
            "SELECT organisation_id, operation, transaction_key, state, "
            "execution_authorization_id, claimed_at, receipt_sequence, "
            "updated_at, upstream_status FROM receiver_transactions"
        )
        params: tuple[Any, ...] = ()
        if open_only:
            sql += " WHERE state IN (?, ?)"
            params = tuple(sorted(OPEN_STATES))
        sql += " ORDER BY claimed_at, receipt_sequence"
        names = (
            "organisation_id",
            "operation",
            "transaction_key",
            "state",
            "execution_authorization_id",
            "claimed_at",
            "receipt_sequence",
            "updated_at",
            "upstream_status",
        )
        with closing(self._connect()) as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(zip(names, row, strict=True)) for row in rows]

    def transaction_events(
        self, organisation_id: str, operation: str, transaction_key: str
    ) -> list[dict[str, Any]]:
        names = (
            "at",
            "from_state",
            "to_state",
            "execution_authorization_id",
            "upstream_status",
            "actor",
            "note",
        )
        with closing(self._connect()) as conn:
            rows = conn.execute(
                "SELECT at, from_state, to_state, execution_authorization_id, "
                "upstream_status, actor, note FROM receiver_transaction_events "
                "WHERE organisation_id = ? AND operation = ? AND transaction_key = ? "
                "ORDER BY id",
                (organisation_id, operation, transaction_key),
            ).fetchall()
        return [dict(zip(names, row, strict=True)) for row in rows]

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
