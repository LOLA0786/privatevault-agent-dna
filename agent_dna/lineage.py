"""Server-derived lineage for multi-agent flows (ADR 0021, lineage PR 2).

Why this exists
---------------
The cross-agent invariants (CABI) correlate a flow by a caller-chosen
``execution_id`` held in an evictable in-memory window. Three confirmed
bypasses follow from that: approve under a fresh id, flood the window
until the initiate is evicted, or open junk ids until another agent's
window is evicted.

Lineage replaces "the caller says these belong together" with "the
server recorded these together":

* An approve-type decide must name the sealed record it approves
  (``lineage.approves = <record_hash>``). The maker is read from the
  server's own row for that record, never from the request.
* Rows live in SQLite. Nothing is evicted; a restart changes nothing.
* Each initiate can be approved at most once (a UNIQUE claim).
* Agent ids are compared in folded form (``agent_dna.identity``).

Modes (``PV_LINEAGE``): ``off`` (default), ``shadow`` (record and report
findings, never change a verdict), ``enforce`` (findings BLOCK). Lineage
can only escalate a verdict; it never relaxes one.

Evidence (PR 3): every lineage row is also a sealed event in a per-flow
hash chain (``pv-lineage-event/0.1``), signed with the receipt signer when
one is configured. ``GET /v1/flows/{flow_id}`` exports a flow and
``tools/verify_lineage.py`` re-checks chain, signatures and the dual-control
rule offline, without importing this package.

Not yet (later PRs): delegation chains, per-flow budgets, loop detection fed
from server rows.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .advisory import Severity
from .decision import Decision, DecisionResult
from .identity import fold_agent_id
from .multi_agent.dual_control import is_approve_intent, is_initiate_intent

LINEAGE_ENV = "PV_LINEAGE"
LINEAGE_MODES = ("off", "shadow", "enforce")
TRIGGERED_BY_LINEAGE = "lineage_invariant"

APPROVE_UNBOUND = "LINEAGE_APPROVE_UNBOUND"
REFERENCE_UNKNOWN = "LINEAGE_REFERENCE_UNKNOWN"
APPROVE_TARGET_NOT_INITIATE = "LINEAGE_APPROVE_TARGET_NOT_INITIATE"
MAKER_EQUALS_CHECKER = "LINEAGE_MAKER_EQUALS_CHECKER"
ALREADY_APPROVED = "LINEAGE_INITIATE_ALREADY_APPROVED"

LINEAGE_EVENT_SPEC = "pv-lineage-event/0.1"
LINEAGE_GENESIS = "0" * 64
# Domain separation: an event hash can never equal a decision record hash
# or a manifest hash signed by the same key.
_EVENT_DOMAIN = b"pv-lineage-event/0.1\n"
# Columns added by PR 3; ALTERed into databases created by PR 2.
_SEALED_COLUMNS = {
    "seq": "INTEGER",
    "prev_event_hash": "TEXT",
    "event_hash": "TEXT",
    "event_json": "TEXT",
    "envelope_json": "TEXT",
}


def canonical_event_bytes(event: dict[str, Any]) -> bytes:
    return json.dumps(
        event, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def lineage_event_hash(event: dict[str, Any]) -> str:
    return hashlib.sha256(_EVENT_DOMAIN + canonical_event_bytes(event)).hexdigest()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS lineage_events (
    record_hash          TEXT PRIMARY KEY,
    flow_id              TEXT NOT NULL,
    decision_id          TEXT NOT NULL,
    agent_norm           TEXT NOT NULL,
    capability           TEXT NOT NULL,
    intent               TEXT NOT NULL CHECK (intent IN ('initiate','approve','other')),
    decision             TEXT NOT NULL,
    parent_record_hash   TEXT,
    approves_record_hash TEXT,
    occurred_at          REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS lineage_events_flow ON lineage_events (flow_id);
CREATE TABLE IF NOT EXISTS lineage_dual_control (
    initiate_record_hash TEXT PRIMARY KEY,
    approver_agent_norm  TEXT NOT NULL,
    approver_record_hash TEXT,
    claimed_at           REAL NOT NULL
);
"""


def _secure_profile() -> bool:
    return os.getenv("PV_SECURE_PROFILE", "0").lower() in ("1", "true", "yes", "on")


def lineage_mode() -> str:
    """Configured lineage mode.

    Under ``PV_SECURE_PROFILE=1`` the default is ``enforce`` and anything
    weaker refuses to start: a control that is off or only reporting gives no
    blocking guarantee, so the secure profile cannot claim it.
    """
    raw = os.getenv(LINEAGE_ENV)
    default = "enforce" if _secure_profile() else "off"
    mode = (raw or default).strip().lower() or default
    if mode not in LINEAGE_MODES:
        raise ValueError(f"{LINEAGE_ENV} must be one of {LINEAGE_MODES}, got {mode!r}")
    if _secure_profile() and mode != "enforce":
        raise RuntimeError(
            f"PV_SECURE_PROFILE=1 requires {LINEAGE_ENV}=enforce (got {mode!r}); "
            "maker != checker gives no blocking guarantee in off or shadow mode"
        )
    return mode


def lineage_manifest(mode: str, attached: bool) -> dict[str, str]:
    """Composition-manifest entry, reported by GET /v1/runtime."""
    if not attached:
        return {
            "status": "not_attached",
            "mode": mode,
            "detail": f"{LINEAGE_ENV}={mode}; server-derived dual control is off",
        }
    detail = {
        "enforce": "server-derived maker != checker BLOCKs (ADR 0021)",
        "shadow": "findings reported only; NO blocking guarantee",
    }[mode]
    return {
        "status": "enforced" if mode == "enforce" else "shadow",
        "mode": mode,
        "detail": detail,
    }


def _bare(record_hash: str) -> str:
    return record_hash[7:] if record_hash.startswith("sha256:") else record_hash


def intent_of(capability: str) -> str:
    if is_approve_intent(capability):
        return "approve"
    if is_initiate_intent(capability):
        return "initiate"
    return "other"


@dataclass
class LineageFinding:
    code: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "detail": self.detail}


@dataclass
class LineageContext:
    """What the server resolved for one decide, before it is recorded."""

    agent_norm: str
    capability: str
    intent: str
    flow_id: str | None  # None: this decide opens a new flow
    parent_record_hash: str | None = None
    approves_record_hash: str | None = None
    findings: list[LineageFinding] = field(default_factory=list)

    def report(self, mode: str) -> dict[str, Any]:
        return {
            "mode": mode,
            "flow_id": self.flow_id,
            "intent": self.intent,
            "findings": [f.to_dict() for f in self.findings],
        }


class LineageLedger:
    """Durable lineage rows next to the decision store (same SQLite file)."""

    def __init__(self, path: str | Path, signer: Any = None) -> None:
        self.path = Path(path)
        self.signer = signer  # ReceiptSigner-compatible (sign_hash), or None
        self._local = threading.local()
        self._conn.executescript(_SCHEMA)
        existing = {
            row[1] for row in self._conn.execute("PRAGMA table_info(lineage_events)")
        }
        for column, kind in _SEALED_COLUMNS.items():
            if column not in existing:
                self._conn.execute(
                    f"ALTER TABLE lineage_events ADD COLUMN {column} {kind}"
                )
        self._conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS lineage_events_flow_seq "
            "ON lineage_events (flow_id, seq)"
        )
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

    # ---- reads -------------------------------------------------------------

    def event(self, record_hash: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT record_hash, flow_id, decision_id, agent_norm, capability, "
            "intent, decision FROM lineage_events WHERE record_hash = ?",
            (_bare(record_hash),),
        ).fetchone()
        if row is None:
            return None
        keys = (
            "record_hash",
            "flow_id",
            "decision_id",
            "agent_norm",
            "capability",
            "intent",
            "decision",
        )
        return dict(zip(keys, row, strict=True))

    def approval_claimed(self, initiate_record_hash: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM lineage_dual_control WHERE initiate_record_hash = ?",
            (_bare(initiate_record_hash),),
        ).fetchone()
        return row is not None

    def flow_events(self, flow_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT record_hash, agent_norm, capability, intent, decision, "
            "approves_record_hash FROM lineage_events WHERE flow_id = ? "
            "ORDER BY occurred_at, record_hash",
            (flow_id,),
        ).fetchall()
        keys = (
            "record_hash",
            "agent_norm",
            "capability",
            "intent",
            "decision",
            "approves_record_hash",
        )
        return [dict(zip(keys, row, strict=True)) for row in rows]

    # ---- resolve (before the decision is recorded) --------------------------

    def resolve(
        self,
        *,
        agent_id: str,
        capability: str,
        lineage: dict[str, Any] | None,
    ) -> LineageContext:
        lineage = lineage or {}
        ctx = LineageContext(
            agent_norm=fold_agent_id(agent_id),
            capability=capability,
            intent=intent_of(capability),
            flow_id=None,
        )
        parent = lineage.get("parent_record_hash")
        approves = lineage.get("approves")

        if parent:
            row = self.event(str(parent))
            if row is None:
                ctx.findings.append(
                    LineageFinding(
                        REFERENCE_UNKNOWN,
                        "lineage.parent_record_hash names no recorded decision",
                    )
                )
            else:
                ctx.parent_record_hash = row["record_hash"]
                ctx.flow_id = row["flow_id"]

        if ctx.intent == "approve":
            if not approves:
                ctx.findings.append(
                    LineageFinding(
                        APPROVE_UNBOUND,
                        "an approve-type action must name the sealed decision it "
                        "approves (lineage.approves)",
                    )
                )
            else:
                initiate = self.event(str(approves))
                if initiate is None:
                    ctx.findings.append(
                        LineageFinding(
                            REFERENCE_UNKNOWN,
                            "lineage.approves names no recorded decision",
                        )
                    )
                elif initiate["intent"] != "initiate":
                    ctx.findings.append(
                        LineageFinding(
                            APPROVE_TARGET_NOT_INITIATE,
                            "lineage.approves must name an initiate-type decision",
                        )
                    )
                else:
                    ctx.approves_record_hash = initiate["record_hash"]
                    ctx.flow_id = initiate["flow_id"]
                    if initiate["agent_norm"] == ctx.agent_norm:
                        ctx.findings.append(
                            LineageFinding(
                                MAKER_EQUALS_CHECKER,
                                f"maker==checker: {initiate['agent_norm']} "
                                "initiated the decision it is approving",
                            )
                        )
                    elif self.approval_claimed(initiate["record_hash"]):
                        ctx.findings.append(
                            LineageFinding(
                                ALREADY_APPROVED,
                                "this initiate has already been approved once",
                            )
                        )
        elif approves:
            ctx.findings.append(
                LineageFinding(
                    APPROVE_TARGET_NOT_INITIATE,
                    "lineage.approves is only valid on an approve-type capability",
                )
            )
        return ctx

    # ---- writes ------------------------------------------------------------

    def claim_approval(self, ctx: LineageContext) -> bool:
        """Atomically reserve the one approval of ctx.approves_record_hash."""
        if ctx.approves_record_hash is None:
            return True
        conn = self._conn
        try:
            conn.execute(
                "INSERT INTO lineage_dual_control "
                "(initiate_record_hash, approver_agent_norm, claimed_at) "
                "VALUES (?, ?, ?)",
                (ctx.approves_record_hash, ctx.agent_norm, time.time()),
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            conn.rollback()
            return False

    def record(
        self,
        ctx: LineageContext,
        *,
        record_hash: str,
        decision_id: str,
        decision: str,
        claimed: bool,
    ) -> str:
        """Persist a sealed, chained event; returns the flow id.

        The chain position (seq, prev_event_hash) is read and written inside
        one ``BEGIN IMMEDIATE`` transaction, so concurrent decides in the
        same flow cannot fork the chain.
        """
        bare = _bare(record_hash)
        flow_id = ctx.flow_id or f"flow:{bare}"
        now = time.time()
        conn = self._conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            head = conn.execute(
                "SELECT seq, event_hash FROM lineage_events WHERE flow_id = ? "
                "AND seq IS NOT NULL ORDER BY seq DESC LIMIT 1",
                (flow_id,),
            ).fetchone()
            seq = 1 if head is None else int(head[0]) + 1
            prev = LINEAGE_GENESIS if head is None else str(head[1])
            event = {
                "spec": LINEAGE_EVENT_SPEC,
                "flow_id": flow_id,
                "seq": seq,
                "prev_event_hash": prev,
                "record_hash": bare,
                "decision_id": decision_id,
                "agent": ctx.agent_norm,
                "capability": ctx.capability,
                "intent": ctx.intent,
                "decision": decision,
                "parent_record_hash": ctx.parent_record_hash,
                "approves_record_hash": ctx.approves_record_hash,
                "occurred_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            }
            event_hash = lineage_event_hash(event)
            envelope = (
                self.signer.sign_hash(event_hash).to_dict()
                if self.signer is not None
                else None
            )
            conn.execute(
                "INSERT INTO lineage_events (record_hash, flow_id, decision_id, "
                "agent_norm, capability, intent, decision, parent_record_hash, "
                "approves_record_hash, occurred_at, seq, prev_event_hash, "
                "event_hash, event_json, envelope_json) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    bare,
                    flow_id,
                    decision_id,
                    ctx.agent_norm,
                    ctx.capability,
                    ctx.intent,
                    decision,
                    ctx.parent_record_hash,
                    ctx.approves_record_hash,
                    now,
                    seq,
                    prev,
                    event_hash,
                    canonical_event_bytes(event).decode("utf-8"),
                    json.dumps(envelope, sort_keys=True) if envelope else None,
                ),
            )
            if claimed and ctx.approves_record_hash is not None:
                conn.execute(
                    "UPDATE lineage_dual_control SET approver_record_hash = ? "
                    "WHERE initiate_record_hash = ?",
                    (bare, ctx.approves_record_hash),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        ctx.flow_id = flow_id
        return flow_id

    def export_flow(self, flow_id: str) -> list[dict[str, Any]]:
        """Sealed events of one flow in chain order, for offline audit."""
        rows = self._conn.execute(
            "SELECT event_json, event_hash, envelope_json FROM lineage_events "
            "WHERE flow_id = ? ORDER BY seq IS NULL, seq, occurred_at",
            (flow_id,),
        ).fetchall()
        out: list[dict[str, Any]] = []
        for event_json, event_hash, envelope_json in rows:
            out.append(
                {
                    # None marks a row recorded before events were sealed;
                    # the verifier refuses it rather than trusting it.
                    "event": json.loads(event_json) if event_json else None,
                    "event_hash": event_hash,
                    "envelope": json.loads(envelope_json) if envelope_json else None,
                }
            )
        return out


_RANK = {"allow": 0, "require_approval": 1, "block": 2}


def escalate_with_lineage(
    result: DecisionResult, findings: list[LineageFinding]
) -> DecisionResult:
    """BLOCK on any finding. Never relaxes an existing verdict."""
    if not findings or result.decision is Decision.BLOCK:
        return result
    return DecisionResult(
        decision=Decision.BLOCK,
        triggered_by=TRIGGERED_BY_LINEAGE,
        reason="; ".join(f"{f.code}: {f.detail}" for f in findings),
        capability=result.capability,
        agent_id=result.agent_id,
        drift_score=result.drift_score,
        severity=Severity.CRITICAL,
        advisory_reasons=list(result.advisory_reasons),
        evidence=result.evidence,
        grant_id=result.grant_id,
    )
