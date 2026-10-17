"""
PostgresDecisionStore -- the decision ledger on PostgreSQL.

Same contract as SQLiteDecisionStore (append/load/load_graph, the
single-use consume and mint claims, suspensions, chain heads), so the
recorder and the API do not know which one they have. Selected with
PV_DATABASE_URL; SQLite remains the default.

What carries over unchanged, and how:

* The record body is stored verbatim as canonical JSON TEXT (not jsonb),
  so export_jsonl() reproduces byte-identical records for the verifier.
* Uniqueness that SQLite enforces under BEGIN IMMEDIATE is enforced here
  by the same unique constraints: one record per (agent, prev_hash), one
  execution event per decision, one consume per permit, one approval use,
  one mint per decision.
* Where SQLite relied on BEGIN IMMEDIATE serialising ALL writers to make
  a read-then-write decision safe, this store takes a narrow transaction
  advisory lock instead: per decision for mint vs. execution outcome, and
  per suspension scope for suspend vs. consume (consumers share, a
  suspension is exclusive). Locks are taken in a fixed order.

Connections come from a pool; every method is one transaction.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from .decision_graph import DecisionGraph
from .decision_record import GENESIS_HASH, DecisionRecord
from .execution_record import ExecutionEvent
from .sqlite_store import MINT_COLUMNS, _check_scopes, classify_mint_row

try:  # optional dependency: pip install 'privatevault-agent-dna[postgres]'
    import psycopg
    from psycopg import errors as pg_errors
    from psycopg_pool import ConnectionPool
except ImportError:  # pragma: no cover - exercised only without the extra
    psycopg = None  # type: ignore[assignment]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    seq          BIGSERIAL PRIMARY KEY,
    kind         TEXT NOT NULL,
    record_id    TEXT NOT NULL,
    agent_id     TEXT NOT NULL,
    capability   TEXT,
    decision     TEXT,
    decision_ref TEXT,
    prev_hash    TEXT,
    record_hash  TEXT NOT NULL,
    body         TEXT NOT NULL,
    CONSTRAINT records_record_id_key UNIQUE (record_id)
);
CREATE INDEX IF NOT EXISTS idx_agent ON records(agent_id);
CREATE INDEX IF NOT EXISTS idx_capability ON records(capability);
CREATE INDEX IF NOT EXISTS idx_decision ON records(decision);
CREATE INDEX IF NOT EXISTS idx_record_hash ON records(record_hash);
CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_prevhash
    ON records(agent_id, prev_hash) WHERE kind = 'decision';
CREATE UNIQUE INDEX IF NOT EXISTS idx_execution_per_decision
    ON records(decision_ref) WHERE kind = 'execution';
CREATE TABLE IF NOT EXISTS envelopes (
    record_hash TEXT PRIMARY KEY,
    agent_id    TEXT NOT NULL,
    envelope    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS execution_authorization_consume (
    execution_authorization_id TEXT PRIMARY KEY,
    organisation_id            TEXT NOT NULL,
    consumed_at                TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS execution_authorization_mint (
    decision_id                TEXT PRIMARY KEY,
    organisation_id            TEXT NOT NULL,
    agent_id                   TEXT NOT NULL,
    principal_id               TEXT NOT NULL,
    bindings_digest            TEXT NOT NULL,
    execution_authorization_id TEXT NOT NULL UNIQUE,
    authorization_json         TEXT NOT NULL,
    expires_at                 TEXT NOT NULL,
    minted_at                  TEXT NOT NULL,
    trust_bundle_json          TEXT,
    trust_bundle_digest        TEXT
);
CREATE TABLE IF NOT EXISTS approval_consume (
    approval_artifact_digest TEXT PRIMARY KEY,
    organisation_id          TEXT NOT NULL,
    consumed_at              TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS suspensions (
    scope_kind   TEXT NOT NULL,
    scope_id     TEXT NOT NULL,
    reason       TEXT NOT NULL,
    suspended_by TEXT NOT NULL,
    suspended_at TEXT NOT NULL,
    PRIMARY KEY (scope_kind, scope_id)
);
"""

# Any fixed key: serialises schema creation when several instances start.
_SCHEMA_LOCK = "pv:schema:decision-store"

_INSERT_RECORD = (
    "INSERT INTO records (kind, record_id, agent_id, capability, decision, "
    "decision_ref, prev_hash, record_hash, body) "
    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
)
_INSERT_ENVELOPE = (
    "INSERT INTO envelopes (record_hash, agent_id, envelope) VALUES (%s, %s, %s)"
)


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _lock(cur: Any, key: str, *, shared: bool = False) -> None:
    fn = "pg_advisory_xact_lock_shared" if shared else "pg_advisory_xact_lock"
    cur.execute(f"SELECT {fn}(hashtextextended(%s, 0))", (key,))


def _decision_lock_key(decision_id: str) -> str:
    return f"pv:decision:{decision_id}"


def _scope_lock_key(kind: str, scope_id: str) -> str:
    return f"pv:scope:{kind}:{scope_id}"


def _constraint(exc: Exception) -> str:
    diag = getattr(exc, "diag", None)
    return str(getattr(diag, "constraint_name", "") or "")


def _integrity_detail(exc: Exception) -> str:
    name = _constraint(exc)
    if name == "idx_execution_per_decision":
        return "duplicate execution event for this decision"
    if name == "records_record_id_key":
        return "duplicate record id"
    if name == "idx_agent_prevhash":
        return "chain head already extended from this prev_hash"
    if name == "envelopes_pkey":
        return "duplicate envelope for this record"
    return f"integrity violation ({name or 'unknown constraint'})"


class PostgresDecisionStore:
    """Decision ledger on PostgreSQL (see module docstring)."""

    SUPPORTS_ENVELOPES = True

    def __init__(self, dsn: str, *, min_size: int = 1, max_size: int = 10) -> None:
        if psycopg is None:
            raise RuntimeError(
                "PV_DATABASE_URL needs the postgres extra: "
                "pip install 'privatevault-agent-dna[postgres]'"
            )
        if not dsn.startswith(("postgresql://", "postgres://")):
            raise ValueError("PV_DATABASE_URL must be a postgresql:// URL")
        self._pool = ConnectionPool(
            dsn,
            min_size=min_size,
            max_size=max_size,
            kwargs={"autocommit": False},
            open=True,
        )
        with self._pool.connection() as conn, conn.cursor() as cur:
            _lock(cur, _SCHEMA_LOCK)
            cur.execute(_SCHEMA)

    # ---- helpers ----------------------------------------------------------

    def _fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> Any:
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchone()

    def _fetchall(self, sql: str, params: tuple[Any, ...] = ()) -> list[Any]:
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(sql, params)
            return list(cur.fetchall())

    @staticmethod
    def _record_params(d: dict[str, Any], body: str) -> tuple[Any, ...]:
        return (
            d.get("kind", "decision"),
            d.get("decision_id") or d.get("event_id"),
            d["agent_id"],
            d.get("capability"),
            d.get("decision"),
            d.get("decision_ref"),
            d.get("prev_hash"),
            d["record_hash"],
            body,
        )

    # ---- write ------------------------------------------------------------

    def append(self, record: Any, envelope: dict[str, Any] | None = None) -> None:
        """Record and envelope in ONE transaction (audit set 4). An
        execution event takes its decision's lock so it cannot interleave
        with a mint deciding on that decision's outcome."""
        if not record.verify():
            raise ValueError("record is unsealed or tampered; refusing to persist")
        d = record.to_dict()
        body = _canonical(d)
        try:
            with self._pool.connection() as conn, conn.cursor() as cur:
                if d.get("kind") == "execution" and d.get("decision_ref"):
                    _lock(cur, _decision_lock_key(str(d["decision_ref"])))
                cur.execute(_INSERT_RECORD, self._record_params(d, body))
                if envelope is not None:
                    cur.execute(
                        _INSERT_ENVELOPE,
                        (d["record_hash"], d["agent_id"], _canonical(envelope)),
                    )
        except pg_errors.UniqueViolation as e:
            raise ValueError(_integrity_detail(e)) from e

    def append_atomic(
        self, record: Any, envelope: dict[str, Any] | None = None
    ) -> bool:
        """Multi-writer append for decision records. False when another
        writer already extended this agent's chain from the same prev_hash
        (the caller re-reads the head and retries); any other uniqueness
        failure is corruption and raises."""
        if not record.verify():
            raise ValueError("record is unsealed or tampered; refusing to persist")
        d = record.to_dict()
        if d.get("kind", "decision") != "decision":
            raise ValueError(
                "append_atomic is for decision records only -- "
                "execution events use append() (anchored, not chained)"
            )
        body = _canonical(d)
        try:
            with self._pool.connection() as conn, conn.cursor() as cur:
                cur.execute(_INSERT_RECORD, self._record_params(d, body))
                if envelope is not None:
                    cur.execute(
                        _INSERT_ENVELOPE,
                        (d["record_hash"], d["agent_id"], _canonical(envelope)),
                    )
            return True
        except pg_errors.UniqueViolation as e:
            if _constraint(e) == "idx_agent_prevhash":
                return False
            raise ValueError(_integrity_detail(e)) from e

    def _claim(self, table: str, column: str, key: str, org: str, at: str) -> bool:
        try:
            with self._pool.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    f"INSERT INTO {table} ({column}, organisation_id, consumed_at) "
                    "VALUES (%s, %s, %s)",
                    (key, org, at),
                )
            return True
        except pg_errors.UniqueViolation:
            return False

    def try_consume_execution_authorization(
        self,
        execution_authorization_id: str,
        *,
        organisation_id: str,
        consumed_at: str,
    ) -> bool:
        if not execution_authorization_id:
            raise ValueError("execution_authorization_id is required")
        return self._claim(
            "execution_authorization_consume",
            "execution_authorization_id",
            execution_authorization_id,
            organisation_id,
            consumed_at,
        )

    def try_consume_approval(
        self,
        approval_artifact_digest: str,
        *,
        organisation_id: str,
        consumed_at: str,
    ) -> bool:
        if not approval_artifact_digest:
            raise ValueError("approval_artifact_digest is required")
        return self._claim(
            "approval_consume",
            "approval_artifact_digest",
            approval_artifact_digest,
            organisation_id,
            consumed_at,
        )

    def suspend(
        self,
        scope_kind: str,
        scope_id: str,
        *,
        reason: str,
        suspended_by: str,
        suspended_at: str,
    ) -> bool:
        _check_scopes(((scope_kind, scope_id),))
        if not reason or not suspended_by:
            raise ValueError("reason and suspended_by are required")
        with self._pool.connection() as conn, conn.cursor() as cur:
            _lock(cur, _scope_lock_key(scope_kind, scope_id))
            cur.execute(
                "INSERT INTO suspensions "
                "(scope_kind, scope_id, reason, suspended_by, suspended_at) "
                "VALUES (%s, %s, %s, %s, %s) ON CONFLICT DO NOTHING",
                (scope_kind, scope_id, reason, suspended_by, suspended_at),
            )
            return bool(cur.rowcount == 1)

    def try_consume_unless_suspended(
        self,
        execution_authorization_id: str,
        *,
        organisation_id: str,
        consumed_at: str,
        scopes: tuple[tuple[str, str], ...],
    ) -> tuple[str, str | None]:
        """Suspension check and consume in ONE transaction. Shared scope
        locks order this claim against any suspension of those scopes."""
        if not execution_authorization_id:
            raise ValueError("execution_authorization_id is required")
        _check_scopes(scopes)
        try:
            with self._pool.connection() as conn, conn.cursor() as cur:
                for kind, sid in sorted(set(scopes)):
                    _lock(cur, _scope_lock_key(kind, sid), shared=True)
                for kind, sid in scopes:
                    cur.execute(
                        "SELECT scope_kind, scope_id, reason FROM suspensions "
                        "WHERE scope_kind = %s AND scope_id = %s",
                        (kind, sid),
                    )
                    row = cur.fetchone()
                    if row is not None:
                        conn.rollback()
                        return "suspended", f"{row[0]}:{row[1]} suspended ({row[2]})"
                cur.execute(
                    "INSERT INTO execution_authorization_consume "
                    "(execution_authorization_id, organisation_id, consumed_at) "
                    "VALUES (%s, %s, %s)",
                    (execution_authorization_id, organisation_id, consumed_at),
                )
            return "consumed", None
        except pg_errors.UniqueViolation:
            return "already_consumed", None

    def claim_or_replay_mint(
        self,
        *,
        decision_id: str,
        organisation_id: str,
        agent_id: str,
        principal_id: str,
        bindings_digest: str,
        now: datetime,
        expires_at: str,
        minted_at: str,
        authorization_factory: Callable[[], dict[str, Any]],
        trust_bundle: dict[str, Any] | None = None,
    ) -> tuple[str, dict[str, Any] | None, dict[str, Any] | None]:
        """One stored permit per decision. The decision lock orders this
        against a concurrent execution outcome and a concurrent mint, so
        the status read and the insert see one consistent state."""
        from agent_dna.authority_v01 import canonicalize, sha256_digest
        from agent_dna.authorize_binding import dump_stored_authorization

        with self._pool.connection() as conn, conn.cursor() as cur:
            _lock(cur, _decision_lock_key(decision_id))

            def status_of(did: str) -> str | None:
                return self._execution_status(cur, did)

            def consumed(auth_id: str) -> bool:
                cur.execute(
                    "SELECT 1 FROM execution_authorization_consume "
                    "WHERE execution_authorization_id = %s",
                    (auth_id,),
                )
                return cur.fetchone() is not None

            if status_of(decision_id) == "indeterminate":
                return "indeterminate", None, None
            cur.execute(
                f"SELECT {MINT_COLUMNS} FROM execution_authorization_mint "
                "WHERE decision_id = %s",
                (decision_id,),
            )
            row = cur.fetchone()
            if row is not None:
                return classify_mint_row(
                    tuple(row),
                    execution_status=status_of,
                    is_consumed=consumed,
                    bindings_digest=bindings_digest,
                    principal_id=principal_id,
                    now=now,
                )
            authorization = authorization_factory()
            blob = dump_stored_authorization(authorization)
            if trust_bundle is None:
                bundle_json = bundle_digest = None
                stored_bundle = None
            else:
                bundle_json = canonicalize(trust_bundle).decode("utf-8")
                bundle_digest = sha256_digest(trust_bundle)
                stored_bundle = json.loads(bundle_json)
                if bundle_digest != authorization.get("trust_bundle_digest"):
                    conn.rollback()
                    return "trust_bundle_digest_mismatch", None, None
            cur.execute(
                f"INSERT INTO execution_authorization_mint ({MINT_COLUMNS}) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    decision_id,
                    organisation_id,
                    agent_id,
                    principal_id,
                    bindings_digest,
                    authorization["execution_authorization_id"],
                    blob,
                    expires_at,
                    minted_at,
                    bundle_json,
                    bundle_digest,
                ),
            )
            return "created", json.loads(blob), stored_bundle

    # ---- read -------------------------------------------------------------

    @staticmethod
    def _execution_status(cur: Any, decision_id: str) -> str | None:
        cur.execute(
            "SELECT body FROM records WHERE kind = 'execution' AND decision_ref = %s",
            (decision_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        status = json.loads(row[0]).get("status")
        return status if isinstance(status, str) else None

    def decision_execution_status(self, decision_id: str) -> str | None:
        with self._pool.connection() as conn, conn.cursor() as cur:
            return self._execution_status(cur, decision_id)

    def is_execution_authorization_consumed(
        self, execution_authorization_id: str
    ) -> bool:
        return (
            self._fetchone(
                "SELECT 1 FROM execution_authorization_consume "
                "WHERE execution_authorization_id = %s",
                (execution_authorization_id,),
            )
            is not None
        )

    def is_approval_consumed(self, approval_artifact_digest: str) -> bool:
        return (
            self._fetchone(
                "SELECT 1 FROM approval_consume WHERE approval_artifact_digest = %s",
                (approval_artifact_digest,),
            )
            is not None
        )

    def get_envelope(self, record_hash: str) -> dict[str, Any] | None:
        row = self._fetchone(
            "SELECT envelope FROM envelopes WHERE record_hash = %s", (record_hash,)
        )
        return json.loads(row[0]) if row else None

    def load_envelopes(self) -> dict[str, Any]:
        return {
            h: json.loads(env)
            for h, env in self._fetchall("SELECT record_hash, envelope FROM envelopes")
        }

    def iter_decisions(self, since_ts: float | None = None) -> Iterator[dict[str, Any]]:
        for (body,) in self._fetchall(
            "SELECT body FROM records WHERE kind = 'decision' ORDER BY seq"
        ):
            rec = json.loads(body)
            if since_ts is None or rec.get("timestamp", 0.0) >= since_ts:
                yield rec

    def iter_executions(self) -> Iterator[dict[str, Any]]:
        for (body,) in self._fetchall(
            "SELECT body FROM records WHERE kind = 'execution' ORDER BY seq"
        ):
            yield json.loads(body)

    def get_decision(self, decision_id: str) -> dict[str, Any] | None:
        row = self._fetchone(
            "SELECT body FROM records WHERE record_id = %s AND kind = 'decision'",
            (decision_id,),
        )
        return json.loads(row[0]) if row else None

    def get_decision_by_record_hash(self, record_hash: str) -> dict[str, Any] | None:
        bare = record_hash[7:] if record_hash.startswith("sha256:") else record_hash
        row = self._fetchone(
            "SELECT body FROM records WHERE record_hash = %s AND kind = 'decision'",
            (bare,),
        )
        return json.loads(row[0]) if row else None

    def get_chain_head(self, agent_id: str) -> tuple[str | None, str]:
        row = self._fetchone(
            "SELECT record_id, record_hash FROM records "
            "WHERE agent_id = %s AND kind = 'decision' ORDER BY seq DESC LIMIT 1",
            (agent_id,),
        )
        if row is None:
            return None, GENESIS_HASH
        return row[0], row[1]

    def revocation_rows(self) -> tuple[list[tuple[str, str]], dict[str, str]]:
        rows = [
            (str(k), str(i))
            for k, i in self._fetchall("SELECT scope_kind, scope_id FROM suspensions")
        ]
        expiries = {
            str(a): str(e)
            for a, e in self._fetchall(
                "SELECT execution_authorization_id, expires_at "
                "FROM execution_authorization_mint"
            )
        }
        return rows, expiries

    def _rows(self) -> list[str]:
        return [r[0] for r in self._fetchall("SELECT body FROM records ORDER BY seq")]

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
                record = DecisionRecord(protocol_version=protocol_version, **d)
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
        path = Path(path)
        path.write_text("\n".join(self._rows()) + "\n")
        return path

    def export_envelopes_jsonl(self, path: str | Path) -> Path:
        path = Path(path)
        rows = self._fetchall(
            "SELECT e.envelope FROM envelopes AS e "
            "LEFT JOIN records AS r ON r.record_hash = e.record_hash "
            "ORDER BY (r.seq IS NULL), r.seq, e.record_hash"
        )
        path.write_text("".join(f"{row[0]}\n" for row in rows), encoding="utf-8")
        return path

    def ping(self) -> bool:
        self._fetchone("SELECT 1")
        return True

    def close(self) -> None:
        self._pool.close()
