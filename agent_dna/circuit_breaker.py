"""
Circuit breaker (TUE-05 / RBM-06).

Two-phase control, distinct from per-action economics (L4):

  1. pre_gate   — a tripped agent is BLOCKed before any precedence
                  level evaluates. Deterministic, fail-closed,
                  survives process restart (SQLite-backed).
  2. observe    — counters update off the verdict stream after every
                  decision; crossing a threshold trips the breaker.

Trip conditions:
  rate            > max_decisions within window_seconds   (runaway loop)
  volume          cumulative amount within window > cap   (salami drain)
  refusal_thrash  K consecutive non-ALLOW verdicts        (probing agent)

Reset is explicit, capability-gated (breaker.reset), and itself a
hash-chained record. There is no silent auto-reset; an optional
cooldown may be configured but defaults to manual-only.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Union

from .decision import Decision, DecisionResult, Severity

RESET_CAPABILITY = "breaker.reset"
RESET_GROUP_CAPABILITY = "breaker.reset_group"
GENESIS = "0" * 64


@dataclass(frozen=True)
class BreakerConfig:
    max_decisions: Optional[int] = 100          # rate trip; None disables
    window_seconds: float = 10.0
    max_cumulative_amount: Optional[float] = None   # volume trip; None disables
    max_consecutive_refusals: Optional[int] = 5     # thrash trip; None disables
    cooldown_seconds: Optional[float] = None        # None = manual reset only
    #
    # Group (swarm) trip conditions. Membership is DECLARED config,
    # not behavioral inference -- the breaker enforces stated
    # structure; detecting undeclared coordination is a drift/DEPA
    # problem and claiming otherwise would be dishonest.
    #
    groups: Optional[Dict[str, List[str]]] = None
    group_volume_caps: Optional[Dict[str, float]] = None


class CircuitBreaker:
    """SQLite-backed per-agent circuit breaker with a hash-chained
    trip/reset log. In-memory state is deliberately not offered:
    a restart must never clear a trip (restart-as-evasion)."""

    def __init__(
        self,
        path: Union[str, Path],
        config: BreakerConfig = BreakerConfig(),
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.config = config
        self._clock = clock
        self._path = str(path)
        # Thread-local connections — same rationale as
        # SQLiteDecisionStore: sqlite3 connections are not
        # thread-safe; a pre_gate read racing an observe write on a
        # shared connection corrupts cursor state.
        self._local = threading.local()
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS breaker_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                ts REAL NOT NULL,
                decision TEXT NOT NULL,
                amount REAL
            );
            CREATE INDEX IF NOT EXISTS idx_events_agent_ts
                ON breaker_events (agent_id, ts);
            CREATE TABLE IF NOT EXISTS breaker_state (
                agent_id TEXT PRIMARY KEY,
                tripped INTEGER NOT NULL,
                reason TEXT NOT NULL,
                tripped_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS breaker_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                event_type TEXT NOT NULL,   -- trip | reset
                reason TEXT NOT NULL,
                actor TEXT NOT NULL,
                ts REAL NOT NULL,
                prev_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL
            );
            """
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # phase 1: pre-gate
    # ------------------------------------------------------------------

    def pre_gate(self, agent_id: str) -> Optional[str]:
        """Return trip reason if the agent is suspended, else None."""
        row = self._conn.execute(
            "SELECT tripped, reason, tripped_at FROM breaker_state WHERE agent_id = ?",
            (agent_id,),
        ).fetchone()
        if row is None or not row[0]:
            return None
        tripped, reason, tripped_at = row
        cd = self.config.cooldown_seconds
        if cd is not None and (self._clock() - tripped_at) >= cd:
            self._write_reset(agent_id, actor="system:cooldown",
                              reason=f"cooldown {cd}s elapsed")
            return None
        return reason

    # ------------------------------------------------------------------
    # phase 2: observe verdict stream, evaluate trips
    # ------------------------------------------------------------------

    def observe(
        self,
        agent_id: str,
        decision: str,
        amount: Optional[float] = None,
    ) -> Optional[str]:
        """Record one verdict; trip if any threshold is crossed.
        Returns the trip reason if this observation tripped the breaker."""
        now = self._clock()
        self._conn.execute(
            "INSERT INTO breaker_events (agent_id, ts, decision, amount) "
            "VALUES (?, ?, ?, ?)",
            (agent_id, now, decision, amount),
        )
        self._conn.commit()
        reason = self._evaluate(agent_id, now)
        if reason is not None:
            self._trip(agent_id, reason, now)
            return reason
        return self._evaluate_groups(agent_id, now)

    def _evaluate(self, agent_id: str, now: float) -> Optional[str]:
        cfg = self.config
        since = now - cfg.window_seconds

        if cfg.max_decisions is not None:
            (n,) = self._conn.execute(
                "SELECT COUNT(*) FROM breaker_events "
                "WHERE agent_id = ? AND ts >= ?",
                (agent_id, since),
            ).fetchone()
            if n > cfg.max_decisions:
                return (
                    f"rate_trip: {n} decisions in {cfg.window_seconds}s "
                    f"window (limit {cfg.max_decisions})"
                )

        if cfg.max_cumulative_amount is not None:
            (total,) = self._conn.execute(
                "SELECT COALESCE(SUM(amount), 0) FROM breaker_events "
                "WHERE agent_id = ? AND ts >= ? AND amount IS NOT NULL",
                (agent_id, since),
            ).fetchone()
            if total > cfg.max_cumulative_amount:
                return (
                    f"volume_trip: cumulative {total:.2f} in "
                    f"{cfg.window_seconds}s window "
                    f"(cap {cfg.max_cumulative_amount:.2f})"
                )

        if cfg.max_consecutive_refusals is not None:
            k = cfg.max_consecutive_refusals
            rows = self._conn.execute(
                "SELECT decision FROM breaker_events "
                "WHERE agent_id = ? AND decision != 'reserved' "
                "ORDER BY id DESC LIMIT ?",
                (agent_id, k),
            ).fetchall()
            if len(rows) == k and all(r[0] != Decision.ALLOW.value for r in rows):
                return (
                    f"refusal_thrash: {k} consecutive non-allow verdicts"
                )

        return None

    # ------------------------------------------------------------------
    # trip / reset — both are chained records
    # ------------------------------------------------------------------

    def _trip(self, agent_id: str, reason: str, now: float) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO breaker_state "
            "(agent_id, tripped, reason, tripped_at) VALUES (?, 1, ?, ?)",
            (agent_id, reason, now),
        )
        self._append_log(agent_id, "trip", reason, actor="system:breaker", ts=now)
        self._conn.commit()

    def _find_group_breach(self, agent_id: str, now: float):
        """Return (gid, members, reason) for the first breached group
        containing agent_id, or None. Pure query -- no state change."""
        cfg = self.config
        if not cfg.groups or not cfg.group_volume_caps:
            return None
        since = now - cfg.window_seconds
        for gid, members in cfg.groups.items():
            if agent_id not in members:
                continue
            cap = cfg.group_volume_caps.get(gid)
            if cap is None:
                continue
            marks = ",".join("?" * len(members))
            (total,) = self._conn.execute(
                f"SELECT COALESCE(SUM(amount), 0) FROM breaker_events "
                f"WHERE agent_id IN ({marks}) AND ts >= ? "
                f"AND amount IS NOT NULL",
                (*members, since),
            ).fetchone()
            if total > cap:
                return gid, members, (
                    f"group_trip:{gid}: cumulative {total:.2f} across "
                    f"{len(members)} agents in {cfg.window_seconds}s "
                    f"window (cap {cap:.2f})"
                )
        return None

    def _evaluate_groups(self, agent_id: str, now: float) -> Optional[str]:
        """Distributed-drain detection: cumulative volume across a
        DECLARED agent group. Each member's actions may individually
        pass every per-agent check; the aggregate trips the swarm."""
        breach = self._find_group_breach(agent_id, now)
        if breach is None:
            return None
        gid, members, reason = breach
        self._trip_group(gid, members, reason, now)
        return reason

    # ------------------------------------------------------------------
    # transactional preflight (P0-5)
    # ------------------------------------------------------------------

    def reserve(self, agent_id: str, amount: Optional[float]):
        """Pre-execution gate with PROJECTED counters (P0-5).

        Previously the breaker observed AFTER the inner decision, so
        the action that crossed a rate/volume threshold was itself
        returned ALLOW; only the next one blocked -- not a spending
        cap. reserve() runs BEFORE the engine: it inserts a
        reservation row inside BEGIN IMMEDIATE (the write lock
        serializes concurrent callers against the same remaining
        budget), evaluates every counter INCLUDING this action, and
        if the projection crosses a threshold, deletes the
        reservation, trips, and blocks the crossing action itself.

        Returns (trip_reason, None) if blocked, else
        (None, reservation_id) -- pass the id to finalize() with the
        verdict."""
        pre = self.pre_gate(agent_id)
        if pre is not None:
            return pre, None

        conn = self._conn
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute("BEGIN IMMEDIATE")
        try:
            now = self._clock()
            cur = conn.execute(
                "INSERT INTO breaker_events (agent_id, ts, decision, amount) "
                "VALUES (?, ?, 'reserved', ?)",
                (agent_id, now, amount),
            )
            rid = cur.lastrowid
            reason = self._evaluate(agent_id, now)      # projected
            breach = None
            if reason is None:
                breach = self._find_group_breach(agent_id, now)
            if reason is None and breach is None:
                conn.commit()
                return None, rid
            # crossing action: never counts toward the window
            conn.execute("DELETE FROM breaker_events WHERE id = ?", (rid,))
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        if reason is not None:
            self._trip(agent_id, reason, now)
            return reason, None
        gid, members, greason = breach
        self._trip_group(gid, members, greason, now)
        return greason, None

    def finalize(self, reservation_id: Optional[int], decision: str) -> Optional[str]:
        """Convert a reservation into its verdict row and evaluate the
        verdict-dependent (refusal-thrash) trip."""
        if reservation_id is None:
            return None
        row = self._conn.execute(
            "SELECT agent_id FROM breaker_events WHERE id = ?",
            (reservation_id,),
        ).fetchone()
        self._conn.execute(
            "UPDATE breaker_events SET decision = ? WHERE id = ?",
            (decision, reservation_id),
        )
        self._conn.commit()
        if row is None:
            return None
        agent_id = row[0]
        now = self._clock()
        cfg = self.config
        if cfg.max_consecutive_refusals is not None:
            k = cfg.max_consecutive_refusals
            rows = self._conn.execute(
                "SELECT decision FROM breaker_events "
                "WHERE agent_id = ? AND decision != 'reserved' "
                "ORDER BY id DESC LIMIT ?",
                (agent_id, k),
            ).fetchall()
            if len(rows) == k and all(
                r[0] != Decision.ALLOW.value for r in rows
            ):
                reason = f"refusal_thrash: {k} consecutive non-allow verdicts"
                self._trip(agent_id, reason, now)
                return reason
        return None

    def _trip_group(
        self, gid: str, members: List[str], reason: str, now: float
    ) -> None:
        """One chained group_trip record naming the collective cause;
        every member suspended at the existing per-agent pre-gate --
        zero new enforcement machinery."""
        for m in members:
            self._conn.execute(
                "INSERT OR REPLACE INTO breaker_state "
                "(agent_id, tripped, reason, tripped_at) VALUES (?, 1, ?, ?)",
                (m, reason, now),
            )
        self._append_log(gid, "group_trip", reason,
                         actor="system:breaker", ts=now)
        self._conn.commit()

    def reset_group(
        self,
        group_id: str,
        actor_id: str,
        authorize: Callable[[str, str], bool],
    ) -> dict:
        """Group-atomic reset: all members or none, one chained
        record. Requires breaker.reset_group -- deliberately distinct
        from breaker.reset: dissolving a swarm suspension is a bigger
        decision than resetting one noisy agent."""
        if not authorize(actor_id, RESET_GROUP_CAPABILITY):
            raise PermissionError(
                f"actor '{actor_id}' lacks capability "
                f"'{RESET_GROUP_CAPABILITY}'"
            )
        members = (self.config.groups or {}).get(group_id)
        if not members:
            raise ValueError(f"unknown group '{group_id}'")
        now = self._clock()
        for m in members:
            self._conn.execute(
                "UPDATE breaker_state SET tripped = 0 WHERE agent_id = ?",
                (m,),
            )
        record = self._append_log(
            group_id, "group_reset",
            f"authorized group reset ({len(members)} members)",
            actor=actor_id, ts=now,
        )
        self._conn.commit()
        return record

    def reset(
        self,
        agent_id: str,
        actor_id: str,
        authorize: Callable[[str, str], bool],
    ) -> dict:
        """Explicit reset. `authorize(actor_id, RESET_CAPABILITY)` must
        return True — wire this to the real Authorizer/CapabilityRegistry.
        The reset itself becomes a chained record. Raises PermissionError
        on unauthorized attempts; the trip state is untouched."""
        if not authorize(actor_id, RESET_CAPABILITY):
            raise PermissionError(
                f"actor '{actor_id}' lacks capability '{RESET_CAPABILITY}'"
            )
        row = self._conn.execute(
            "SELECT reason FROM breaker_state "
            "WHERE agent_id = ? AND tripped = 1",
            (agent_id,),
        ).fetchone()
        if row and row[0].startswith("group_trip:"):
            raise PermissionError(
                "agent is under a GROUP suspension; a per-agent reset "
                "must not dissolve a swarm suspension one member at a "
                "time -- use reset_group (capability breaker.reset_group)"
            )
        return self._write_reset(agent_id, actor=actor_id,
                                 reason="authorized manual reset")

    def _write_reset(self, agent_id: str, actor: str, reason: str) -> dict:
        now = self._clock()
        self._conn.execute(
            "UPDATE breaker_state SET tripped = 0 WHERE agent_id = ?",
            (agent_id,),
        )
        record = self._append_log(agent_id, "reset", reason, actor=actor, ts=now)
        self._conn.commit()
        return record

    def _append_log(
        self, agent_id: str, event_type: str, reason: str, actor: str, ts: float
    ) -> dict:
        row = self._conn.execute(
            "SELECT record_hash FROM breaker_log ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = row[0] if row else GENESIS
        body = {
            "agent_id": agent_id,
            "event_type": event_type,
            "reason": reason,
            "actor": actor,
            "ts": ts,
            "prev_hash": prev_hash,
        }
        record_hash = hashlib.sha256(
            json.dumps(body, sort_keys=True).encode()
        ).hexdigest()
        self._conn.execute(
            "INSERT INTO breaker_log "
            "(agent_id, event_type, reason, actor, ts, prev_hash, record_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (agent_id, event_type, reason, actor, ts, prev_hash, record_hash),
        )
        body["record_hash"] = record_hash
        return body

    def verify_log(self) -> bool:
        """Walk the trip/reset chain; True iff every link binds."""
        prev = GENESIS
        for row in self._conn.execute(
            "SELECT agent_id, event_type, reason, actor, ts, prev_hash, "
            "record_hash FROM breaker_log ORDER BY id"
        ):
            agent_id, event_type, reason, actor, ts, prev_hash, record_hash = row
            if prev_hash != prev:
                return False
            body = {
                "agent_id": agent_id,
                "event_type": event_type,
                "reason": reason,
                "actor": actor,
                "ts": ts,
                "prev_hash": prev_hash,
            }
            if hashlib.sha256(
                json.dumps(body, sort_keys=True).encode()
            ).hexdigest() != record_hash:
                return False
            prev = record_hash
        return True

    def is_tripped(self, agent_id: str) -> bool:
        return self.pre_gate(agent_id) is not None

    @property
    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None


def _default_amount(action, evidence: Optional[dict]) -> Optional[float]:
    amt = getattr(action, "amount", None)
    if amt is None:
        # P0-5: normal AgentAction amounts live here -- this path was
        # missing, so ordinary payments never reached the breaker
        args = getattr(action, "arguments", None) or {}
        amt = args.get("amount")
    if amt is None and evidence:
        amt = evidence.get("amount")
    try:
        return float(amt) if amt is not None else None
    except (TypeError, ValueError):
        return None


class GuardedEngine:
    """Composable wrapper: pre-gates a DecisionEngine (or anything with
    the same .decide contract) behind a CircuitBreaker, and feeds every
    verdict back into it. No edits to decision.py required."""

    def __init__(
        self,
        engine,
        breaker: CircuitBreaker,
        amount_fn: Callable = _default_amount,
    ) -> None:
        self.engine = engine
        self.breaker = breaker
        self._amount_fn = amount_fn

    def __getattr__(self, name):
        # Transparent proxy: anything the wrapper doesn't define
        # (evidence_engine, scorer, ...) resolves to the real engine,
        # so RuntimeMonitor and friends see an unchanged surface.
        return getattr(self.engine, name)

    def _blocked(self, action, reason: str) -> DecisionResult:
        return DecisionResult(
            decision=Decision.BLOCK,
            triggered_by="circuit_breaker",
            reason=f"agent suspended: {reason}",
            capability=action.capability,
            agent_id=action.agent_id,
            drift_score=0.0,
            severity=Severity.CRITICAL,
        )

    def decide(
        self,
        action,
        prev_capability: Optional[str] = None,
        evidence: Optional[dict] = None,
    ) -> DecisionResult:
        # P0-5: transactional preflight -- the crossing action itself
        # is blocked; concurrent callers serialize against the same
        # remaining budget inside the breaker's write transaction.
        try:
            amount = self._amount_fn(action, evidence)
            reason, rid = self.breaker.reserve(action.agent_id, amount)
        except Exception as exc:
            # a faulting breaker must never become a bypass
            return self._blocked(
                action, f"breaker_fault: {type(exc).__name__}: {exc}"
            )
        if reason is not None:
            return self._blocked(action, reason)
        result = self.engine.decide(action, prev_capability, evidence)
        try:
            self.breaker.finalize(rid, result.decision.value)
        except Exception:
            # the verdict stands; a lost thrash-counter update is a
            # monitoring gap, not an enforcement decision
            pass
        return result
