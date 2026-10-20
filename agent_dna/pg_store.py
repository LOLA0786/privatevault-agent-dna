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
import time
from collections.abc import Callable, Iterator, Sequence
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from .amount import coerce_amount
from .decision_graph import DecisionGraph
from .decision_record import GENESIS_HASH, DecisionRecord
from .execution_record import ExecutionEvent
from .grant_revocation import RevocationResult
from .grant_spend import GrantBudgetExceededError
from .ledger_reads import (
    MAX_PAGE_SIZE,
    READ_INDEXES,
    decision_rows_query,
    lineage_query,
)
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
    consumed_at              TEXT NOT NULL,
    not_after                TEXT
);
-- Databases created before the column existed: claims without a stored
-- expiry cannot mint (fail closed).
ALTER TABLE approval_consume ADD COLUMN IF NOT EXISTS not_after TEXT;
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

    def __init__(
        self,
        dsn: str,
        *,
        min_size: int = 1,
        max_size: int = 10,
        timeout: float = 5.0,
    ) -> None:
        """``timeout``: seconds a request waits for a connection. While the
        database is unreachable every request fails after this long (closed:
        no verdict without the ledger) instead of holding a server thread."""
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
            timeout=timeout,
            kwargs={"autocommit": False, "connect_timeout": max(1, round(timeout))},
            open=True,
        )
        with self._pool.connection() as conn, conn.cursor() as cur:
            _lock(cur, _SCHEMA_LOCK)
            cur.execute(_SCHEMA)
            cur.execute(READ_INDEXES)

    @property
    def pool(self) -> Any:
        """The connection pool, shared by the grant ledgers below."""
        return self._pool

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
        not_after: str | None = None,
    ) -> bool:
        return self.try_consume_approvals(
            [approval_artifact_digest],
            organisation_id=organisation_id,
            consumed_at=consumed_at,
            not_after=not_after,
        )

    def try_consume_approvals(
        self,
        approval_digests: Sequence[str],
        *,
        organisation_id: str,
        consumed_at: str,
        not_after: str | None = None,
    ) -> bool:
        """All-or-nothing claim of several approval digests (ADR 0031)."""
        if not approval_digests or not all(approval_digests):
            raise ValueError("approval digests are required")
        if len(set(approval_digests)) != len(approval_digests):
            raise ValueError("approval digests repeat")
        try:
            with (
                self._pool.connection() as conn,
                conn.transaction(),
                conn.cursor() as cur,
            ):
                for digest in approval_digests:
                    cur.execute(
                        "INSERT INTO approval_consume (approval_artifact_digest, "
                        "organisation_id, consumed_at, not_after) "
                        "VALUES (%s, %s, %s, %s)",
                        (digest, organisation_id, consumed_at, not_after),
                    )
            return True
        except pg_errors.UniqueViolation:
            return False

    def approval_not_after(self, approval_artifact_digest: str) -> str | None:
        """The stored expiry of a consumed approval, or None."""
        row = self._fetchone(
            "SELECT not_after FROM approval_consume WHERE approval_artifact_digest = %s",
            (approval_artifact_digest,),
        )
        return row[0] if row else None

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

    def decision_rows(
        self,
        *,
        agent_id: str | None = None,
        verdict: str | None = None,
        divergent: bool = False,
        after_seq: int = 0,
        limit: int = 100,
    ) -> list[tuple[int, str]]:
        """One page of decision rows (seq, body), indexed (ADR 0029)."""
        sql, params = decision_rows_query(
            placeholder="%s",
            execution_ok="(e.body::jsonb ->> 'status') = 'ok'",
            agent_id=agent_id,
            verdict=verdict,
            divergent=divergent,
            after_seq=after_seq,
            limit=limit,
        )
        return [(int(seq), str(body)) for seq, body in self._fetchall(sql, params)]

    def decision_lineage_rows(
        self, decision_id: str, limit: int = MAX_PAGE_SIZE
    ) -> list[str]:
        """Bodies of a decision and up to ``limit`` ancestors, root-most
        first: one recursive query (ADR 0029)."""
        sql = lineage_query(
            placeholder="%s",
            parent_of="({t}.body::jsonb ->> 'parent_decision')",
            max_depth=limit,
        )
        return [str(body) for (body,) in self._fetchall(sql, (decision_id,))]

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


# ---- grant ledgers -----------------------------------------------------------

_GRANTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS grant_spend (
    grant_id   TEXT PRIMARY KEY,
    spent      TEXT NOT NULL,
    updated_at DOUBLE PRECISION NOT NULL
);
CREATE TABLE IF NOT EXISTS grant_revocations (
    grant_id    TEXT PRIMARY KEY,
    revoked_at  TEXT NOT NULL,
    revoked_by  TEXT NOT NULL,
    reason      TEXT NOT NULL
);
"""


def _ensure_grants_schema(pool: Any) -> None:
    with pool.connection() as conn, conn.cursor() as cur:
        _lock(cur, "pv:schema:grants")
        cur.execute(_GRANTS_SCHEMA)


class PostgresGrantSpendLedger:
    """GrantSpendLedger on PostgreSQL: one budget across every instance.

    The grant's row is locked (SELECT ... FOR UPDATE) for the check-and-add,
    so concurrent spends against one grant serialise and the budget can
    never be exceeded; spends on different grants do not wait on each
    other. Amounts are canonical decimal strings, never floats.
    """

    def __init__(self, pool: Any) -> None:
        self._pool = pool
        _ensure_grants_schema(pool)

    def close(self) -> None:  # the pool belongs to the decision store
        return None

    def spent(self, grant_id: str) -> Decimal:
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT spent FROM grant_spend WHERE grant_id = %s", (grant_id,)
            )
            row = cur.fetchone()
        return Decimal(row[0]) if row else Decimal("0")

    def commit_spend(
        self, grant_id: str, amount: object, budget: object | None
    ) -> Decimal:
        delta = coerce_amount(amount)
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO grant_spend (grant_id, spent, updated_at) "
                "VALUES (%s, '0', %s) ON CONFLICT (grant_id) DO NOTHING",
                (grant_id, time.time()),
            )
            cur.execute(
                "SELECT spent FROM grant_spend WHERE grant_id = %s FOR UPDATE",
                (grant_id,),
            )
            row = cur.fetchone()
            new = Decimal(row[0]) + delta
            if budget is not None and new > coerce_amount(budget):
                conn.rollback()
                raise GrantBudgetExceededError(
                    f"grant {grant_id[:14]} budget exceeded at commit "
                    f"({new} > {coerce_amount(budget)})"
                )
            cur.execute(
                "UPDATE grant_spend SET spent = %s, updated_at = %s WHERE grant_id = %s",
                (str(new), time.time(), grant_id),
            )
        return new


class PostgresGrantRevocationLedger:
    """GrantRevocationLedger on PostgreSQL, same enforcement boundary.

    The revocation row commits first; then every permit minted under the
    grant is suspended in the decision store (same database), and a mint
    racing the revocation re-checks and suspends itself, as with SQLite.
    """

    def __init__(self, pool: Any) -> None:
        self._pool = pool
        _ensure_grants_schema(pool)

    def close(self) -> None:
        return None

    def is_revoked(self, grant_id: str | None) -> dict[str, str] | None:
        if not grant_id:
            return None
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT revoked_at, revoked_by, reason FROM grant_revocations "
                "WHERE grant_id = %s",
                (grant_id,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return {"revoked_at": row[0], "revoked_by": row[1], "reason": row[2]}

    def revoked(self) -> list[dict[str, str]]:
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT grant_id, revoked_at, revoked_by, reason FROM "
                "grant_revocations ORDER BY revoked_at, grant_id"
            )
            rows = cur.fetchall()
        keys = ("grant_id", "revoked_at", "revoked_by", "reason")
        return [dict(zip(keys, row, strict=True)) for row in rows]

    def outstanding_authorizations(self, grant_id: str) -> list[str]:
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT m.execution_authorization_id "
                "FROM execution_authorization_mint AS m "
                "JOIN records AS r ON r.record_id = m.decision_id "
                "WHERE r.kind = 'decision' "
                "AND (r.body::jsonb ->> 'approval_ref') = %s "
                "ORDER BY m.execution_authorization_id",
                (grant_id,),
            )
            return [row[0] for row in cur.fetchall()]

    def revoke(
        self, grant_id: str, *, revoked_by: str, reason: str, store: Any
    ) -> RevocationResult:
        if not grant_id or not revoked_by or not reason:
            raise ValueError("grant_id, revoked_by and reason are required")
        at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        with self._pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO grant_revocations (grant_id, revoked_at, revoked_by, reason) "
                "VALUES (%s, %s, %s, %s) ON CONFLICT DO NOTHING",
                (grant_id, at, revoked_by, reason),
            )
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
