"""
Retrospective policy replay (Part B) — "what would this rule have done
to last month's decisions?"

Part A (shadow.py) answers this going FORWARD on live traffic. Part B
answers it BACKWARD over sealed history -- the CRO question: replay a
candidate rule against the last 30 days and see exactly which past
decisions it would have changed, traceable to the sealed records.

The privacy problem, and how this solves it honestly
----------------------------------------------------
Decision records store arguments_digest (a SHA-256), never raw
arguments -- deliberately, so payment payloads never enter the audit
trail. You cannot re-evaluate a rule against a hash. So replay needs
the rule-relevant INPUTS, which means retaining them somewhere.

We do NOT widen the audit trail. Instead:

  * Retention is OPT-IN per deployment (PV_REPLAY_FIELDS unset =>
    feature off, nothing stored).
  * The customer declares EXACTLY which argument fields to retain --
    a bounded allowlist (e.g. ["amount", "currency", "target_type"]),
    never the whole payload. A field not on the list is never stored.
  * The sidecar is a SEPARATE store from the decision chain, keyed by
    decision_id, so retention policy (shorter TTL, stricter access,
    deletion on request) is governed independently of the immutable
    audit trail.
  * Each retained row records the field allowlist that produced it, so
    an auditor can see precisely what was and was not kept.

This is a data-retention surface a bank's privacy team must approve.
docs/POLICY-REPLAY.md states the boundary; the feature ships OFF.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from typing import Any


@dataclass
class ReplayInputStore:
    """Opt-in, field-scoped retention of rule-relevant inputs, keyed to
    decision_id, in a store SEPARATE from the decision chain."""

    path: str
    retain_fields: list[str]  # the declared allowlist; empty => off

    def __post_init__(self) -> None:
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS replay_inputs (
                decision_id   TEXT PRIMARY KEY,
                ts            REAL NOT NULL,
                agent_id      TEXT NOT NULL,
                capability    TEXT NOT NULL,
                retained      TEXT NOT NULL,   -- JSON: allowlisted fields only
                field_scope   TEXT NOT NULL    -- JSON: the allowlist used
            )
        """)
        self._conn.commit()

    @property
    def enabled(self) -> bool:
        return bool(self.retain_fields)

    def capture(
        self,
        decision_id: str,
        agent_id: str,
        capability: str,
        arguments: dict[str, Any],
    ) -> None:
        """Store ONLY the allowlisted fields present in arguments. A
        field not on retain_fields is never persisted. No-op when the
        feature is off."""
        if not self.enabled:
            return
        retained = {
            k: v for k, v in (arguments or {}).items() if k in self.retain_fields
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO replay_inputs "
            "(decision_id, ts, agent_id, capability, retained, field_scope) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                decision_id,
                time.time(),
                agent_id,
                capability,
                json.dumps(retained, sort_keys=True),
                json.dumps(sorted(self.retain_fields)),
            ),
        )
        self._conn.commit()

    def iter_inputs(self, since_ts: float | None = None):
        """Read-only iteration over retained inputs (policy mining)."""
        q = (
            "SELECT decision_id, ts, agent_id, capability, retained, field_scope "
            "FROM replay_inputs"
        )
        params: tuple = ()
        if since_ts is not None:
            q += " WHERE ts >= ?"
            params = (since_ts,)
        for did, ts, agent, cap, retained, field_scope in self._conn.execute(q, params):
            yield {
                "decision_id": did,
                "ts": ts,
                "agent_id": agent,
                "capability": cap,
                "retained": json.loads(retained),
                "field_scope": json.loads(field_scope),
            }

    def purge_before(self, cutoff_ts: float) -> int:
        """Retention control: delete retained inputs older than cutoff.
        Returns rows removed. (The immutable decision chain is never
        touched by this -- only the opt-in sidecar.)"""
        cur = self._conn.execute("DELETE FROM replay_inputs WHERE ts < ?", (cutoff_ts,))
        self._conn.commit()
        return cur.rowcount

    def close(self) -> None:
        self._conn.close()


@dataclass
class PolicyReplay:
    """Replay a candidate policy over sealed decisions + retained
    inputs. Reports the counterfactual: which past decisions the
    candidate would have changed."""

    store: ReplayInputStore
    decision_store: Any  # SQLiteDecisionStore (source of truth)

    def replay(
        self, candidate, *, since_ts: float | None = None, limit: int | None = None
    ) -> dict[str, Any]:
        if not self.store.enabled:
            return {
                "status": "unavailable",
                "reason": "input retention is OFF for this deployment "
                "(PV_REPLAY_FIELDS unset); retrospective replay "
                "requires opt-in field retention -- see "
                "docs/POLICY-REPLAY.md",
            }

        rows = self._joined_rows(since_ts, limit)
        would_block, would_allow, errors = [], [], 0
        by_cap: dict[str, int] = {}

        for row in rows:
            try:
                pr = candidate.check(
                    agent_id=row["agent_id"],
                    capability=row["capability"],
                    arguments=row["retained"],
                    evidence=None,
                )
                shadow = pr.outcome if getattr(pr, "fired", False) else "allow"
                rule_id = getattr(pr, "matched_rule_id", None)
            except Exception:  # noqa: BLE001
                errors += 1
                continue

            live = row["decision"]
            if shadow in ("block", "require_approval") and live == "allow":
                would_block.append({**row, "shadow": shadow, "rule": rule_id})
                by_cap[row["capability"]] = by_cap.get(row["capability"], 0) + 1
            elif shadow == "allow" and live in ("block", "require_approval"):
                would_allow.append({**row, "shadow": shadow})

        return {
            "status": "ok",
            "replayed": len(rows),
            "field_scope": sorted(self.store.retain_fields),
            "would_newly_block": len(would_block),
            "would_newly_allow": len(would_allow),
            "candidate_errors": errors,
            "unchanged": len(rows) - len(would_block) - len(would_allow) - errors,
            "newly_blocked_by_capability": dict(
                sorted(by_cap.items(), key=lambda kv: -kv[1])
            ),
            "sample_newly_blocked": [
                {
                    "decision_id": r["decision_id"],
                    "capability": r["capability"],
                    "agent_id": r["agent_id"],
                    "live": r["decision"],
                    "shadow": r["shadow"],
                    "rule": r["rule"],
                    "record_hash": r["record_hash"][:12] + "..",
                }
                for r in would_block[:10]
            ],
        }

    def _joined_rows(self, since_ts, limit) -> list[dict[str, Any]]:
        """Join retained inputs to their sealed decision records. The
        decision (allow/block/...) comes from the immutable record;
        the inputs come from the opt-in sidecar."""
        cur = self.store._conn.execute(
            "SELECT decision_id, ts, agent_id, capability, retained "
            "FROM replay_inputs"
            + (" WHERE ts >= ?" if since_ts else "")
            + " ORDER BY ts DESC"
            + (" LIMIT ?" if limit else ""),
            tuple(x for x in (since_ts, limit) if x is not None),
        )
        rows = []
        for did, ts, agent, cap, retained in cur.fetchall():
            rec = self.decision_store.get_decision(did)
            if rec is None:  # input retained but record gone
                continue
            rows.append(
                {
                    "decision_id": did,
                    "ts": ts,
                    "agent_id": agent,
                    "capability": cap,
                    "retained": json.loads(retained),
                    "decision": rec["decision"],
                    "record_hash": rec["record_hash"],
                }
            )
        return rows
