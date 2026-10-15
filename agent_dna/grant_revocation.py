"""Durable grant revocation with a defined enforcement boundary.

Before this module, revoking a grant was an in-memory flag (lost on
restart) and nothing stopped a permit already minted under that grant.

Revoking a grant now takes effect at every point PrivateVault controls:

1. **Decide.** The grant no longer authorises (``GrantRegistry.explain``).
2. **Mint.** ``/v1/authorize`` refuses a sealed ALLOW whose grant is
   revoked, and re-checks after claiming the mint so a revocation that
   races the mint still suspends the new permit.
3. **Dispatch.** Every permit already minted under the grant is durably
   suspended (``suspensions`` scope ``authorization``). The exact-byte
   dispatcher checks suspensions inside the same transaction that consumes
   a permit, so a suspended permit is never sent.

Receivers that hold a permit independently are covered by the signed
revocation list (follow-up PR). Actions already dispatched before the
revocation committed are not reversed: they remain in the audit trail with
their outcome, and the revocation row records when the boundary fell.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS grant_revocations (
    grant_id    TEXT PRIMARY KEY,
    revoked_at  TEXT NOT NULL,
    revoked_by  TEXT NOT NULL,
    reason      TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@dataclass
class RevocationResult:
    grant_id: str
    newly_revoked: bool
    revoked_at: str
    suspended_authorizations: list[str] = field(default_factory=list)


class GrantRevocationLedger:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._local = threading.local()
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    @property
    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.path, timeout=30)
            conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    def is_revoked(self, grant_id: str | None) -> dict[str, str] | None:
        if not grant_id:
            return None
        row = self._conn.execute(
            "SELECT revoked_at, revoked_by, reason FROM grant_revocations "
            "WHERE grant_id = ?",
            (grant_id,),
        ).fetchone()
        if row is None:
            return None
        return {"revoked_at": row[0], "revoked_by": row[1], "reason": row[2]}

    def revoked(self) -> list[dict[str, str]]:
        rows = self._conn.execute(
            "SELECT grant_id, revoked_at, revoked_by, reason FROM "
            "grant_revocations ORDER BY revoked_at, grant_id"
        ).fetchall()
        keys = ("grant_id", "revoked_at", "revoked_by", "reason")
        return [dict(zip(keys, row, strict=True)) for row in rows]

    def outstanding_authorizations(self, grant_id: str) -> list[str]:
        """Permits minted under decisions that executed on this grant."""
        try:
            rows = self._conn.execute(
                "SELECT m.execution_authorization_id "
                "FROM execution_authorization_mint AS m "
                "JOIN records AS r ON r.record_id = m.decision_id "
                "WHERE r.kind = 'decision' "
                "AND json_extract(r.body, '$.approval_ref') = ? "
                "ORDER BY m.execution_authorization_id",
                (grant_id,),
            ).fetchall()
        except sqlite3.OperationalError:
            return []  # no decision store tables in this database yet
        return [row[0] for row in rows]

    def revoke(
        self,
        grant_id: str,
        *,
        revoked_by: str,
        reason: str,
        store: Any,
    ) -> RevocationResult:
        """Record the revocation, then suspend every permit it backs.

        Ordering matters: the revocation row commits first. A mint that
        commits before the scan below is found and suspended; a mint that
        commits after it re-checks revocation and suspends itself.
        """
        if not grant_id or not revoked_by or not reason:
            raise ValueError("grant_id, revoked_by and reason are required")
        at = _now()
        conn = self._conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            cur = conn.execute(
                "INSERT OR IGNORE INTO grant_revocations "
                "(grant_id, revoked_at, revoked_by, reason) VALUES (?, ?, ?, ?)",
                (grant_id, at, revoked_by, reason),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        newly = cur.rowcount == 1
        existing = self.is_revoked(grant_id) or {"revoked_at": at}
        suspended = []
        for ea_id in self.outstanding_authorizations(grant_id):
            store.suspend(
                "authorization",
                ea_id,
                reason=f"grant {grant_id} revoked: {reason}",
                suspended_by=revoked_by,
                suspended_at=existing["revoked_at"],
            )
            suspended.append(ea_id)
        return RevocationResult(grant_id, newly, existing["revoked_at"], suspended)
