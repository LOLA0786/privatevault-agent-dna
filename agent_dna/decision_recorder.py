"""
DecisionRecorder — the single seam between enforcement and audit.

Consumes (AgentAction, DecisionResult), produces a sealed
DecisionRecord, appends it to a DecisionGraph, and maintains
per-agent chain state (prev_hash + parent lineage).

The DecisionEngine never imports this module. The RuntimeMonitor
never requires it. Recording is composed around enforcement,
not into it.
"""

from __future__ import annotations

import random
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .decision import DecisionResult
from .decision_graph import DecisionGraph
from .decision_record import (
    GENESIS_HASH,
    DecisionRecord,
    build_record,
    build_record_v02,
)
from .execution_record import ExecutionEvent, build_execution_event
from .trace import AgentAction


@dataclass
class _ChainState:
    last_decision_id: str | None = None
    last_hash: str = GENESIS_HASH


class DecisionRecorder:
    def __init__(
        self,
        graph: DecisionGraph | None = None,
        store=None,  # optional DecisionStore
        signer=None,  # optional ReceiptSigner
        multi_writer_safe: bool = False,
    ) -> None:
        """multi_writer_safe: when True, every record() call reads the
        chain head LIVE from the store (via store.get_chain_head) and
        writes with store.append_atomic, instead of trusting in-memory
        state. Required for correctness when multiple OS processes
        share one store -- in-memory chain state is per-process and
        cannot see another process's writes. Requires a store that
        implements get_chain_head/append_atomic (SQLiteDecisionStore).
        Single-process deployments should leave this False (default);
        the in-memory fast path is correct and faster for that case."""
        self.graph = graph if graph is not None else DecisionGraph()
        self.store = store
        self.signer = signer
        self.multi_writer_safe = multi_writer_safe
        self.envelopes: dict[str, dict] = {}  # record_hash -> envelope
        # opt-in retrospective-replay input capture (composition sets this)
        self.replay_capture: Callable[[str, str, str, dict[str, Any]], None] | None = (
            None
        )
        self._chains: dict[str, _ChainState] = {}
        if multi_writer_safe and store is None:
            raise ValueError("multi_writer_safe=True requires a store")
        if multi_writer_safe and not hasattr(store, "get_chain_head"):
            raise ValueError(
                "multi_writer_safe=True requires a store implementing "
                "get_chain_head/append_atomic (e.g. SQLiteDecisionStore)"
            )
        if store is not None:
            self.restore_chains()

    def restore_chains(self) -> int:
        """Rebuild the in-memory graph and per-agent chain heads from the
        store. Without this, a process restart would chain the next
        record from GENESIS instead of the last persisted hash — a
        chain break in our own audit trail. Returns records restored."""
        restored = self.store.load_graph()
        if getattr(self.store, "SUPPORTS_ENVELOPES", False):
            self.envelopes = self.store.load_envelopes()
        # adopt the restored graph wholesale (verified record-by-record
        # inside load_graph via graph.add / add_execution)
        self.graph = restored
        count = 0
        for rec in restored:
            chain = self._chains.setdefault(rec.agent_id, _ChainState())
            chain.last_decision_id = rec.decision_id
            chain.last_hash = rec.record_hash
            count += 1
        return count

    def record(
        self,
        action: AgentAction,
        result: DecisionResult,
        anchor_hash: str | None = None,
        *,
        execution_action: dict[str, Any] | None = None,
        dispatch_context: dict[str, Any] | None = None,
    ) -> DecisionRecord:
        """Persist a sealed decision.

        When both ``execution_action`` and ``dispatch_context`` are
        supplied, emits DRP 0.2 (mintable). Otherwise emits DRP 0.1
        (audit-only; cannot authorize). Partial binding is refused.
        """
        if (execution_action is None) ^ (dispatch_context is None):
            raise ValueError(
                "execution_action and dispatch_context must both be "
                "provided for DRP 0.2, or both omitted for audit-only DRP 0.1"
            )
        if self.multi_writer_safe:
            return self._record_multi_writer_safe(
                action,
                result,
                anchor_hash,
                execution_action=execution_action,
                dispatch_context=dispatch_context,
            )
        is_fresh_chain = action.agent_id not in self._chains
        chain = self._chains.setdefault(action.agent_id, _ChainState())

        if execution_action is not None and dispatch_context is not None:
            rec = build_record_v02(
                action,
                result,
                execution_action=execution_action,
                dispatch_context=dispatch_context,
                parent_decision=chain.last_decision_id,
                prev_hash=chain.last_hash,
                anchor_hash=anchor_hash if is_fresh_chain else None,
                request_id=getattr(action, "request_id", None),
            )
        else:
            rec = build_record(
                action,
                result,
                parent_decision=chain.last_decision_id,
                prev_hash=chain.last_hash,
                anchor_hash=anchor_hash if is_fresh_chain else None,
                request_id=getattr(action, "request_id", None),
            )
        # Audit set 4 ordering: sign first (pure function of the
        # sealed record), then persist record AND envelope in ONE
        # store transaction, then update the in-memory graph/heads.
        # A store failure leaves memory untouched; a memory failure
        # after commit leaves the store -- the source of truth --
        # complete, repaired by restore_chains() on restart. The old
        # order (graph -> store -> sign) could commit a record whose
        # envelope lived only in memory.
        env_dict = None
        if self.signer is not None:
            env_dict = self.signer.sign_record(rec).to_dict()
        if self.store is not None:
            if env_dict is not None and getattr(
                self.store, "SUPPORTS_ENVELOPES", False
            ):
                self.store.append(rec, envelope=env_dict)
            else:
                self.store.append(rec)
        self.graph.add(rec)
        if env_dict is not None:
            self.envelopes[rec.record_hash] = env_dict

        chain.last_decision_id = rec.decision_id
        chain.last_hash = rec.record_hash
        if self.replay_capture is not None:
            try:
                self.replay_capture(
                    rec.decision_id,
                    action.agent_id,
                    action.capability,
                    getattr(action, "arguments", {}),
                )
            except Exception:
                pass  # replay capture is diagnostic; never breaks recording
        return rec

    def _record_multi_writer_safe(
        self,
        action: AgentAction,
        result: DecisionResult,
        anchor_hash: str | None = None,
        max_retries: int = 20,
        *,
        execution_action: dict[str, Any] | None = None,
        dispatch_context: dict[str, Any] | None = None,
    ) -> DecisionRecord:
        """Chain head is read fresh from the store on every call --
        never trusts in-memory state, since another process may have
        written since this process last checked. On a lost race
        (store.append_atomic returns False because another writer
        claimed this agent's chain from the same prev_hash first),
        re-reads the now-updated head and retries."""
        for attempt in range(max_retries):
            last_decision_id, last_hash = self.store.get_chain_head(action.agent_id)
            is_fresh_chain = last_decision_id is None
            if execution_action is not None and dispatch_context is not None:
                rec = build_record_v02(
                    action,
                    result,
                    execution_action=execution_action,
                    dispatch_context=dispatch_context,
                    parent_decision=last_decision_id,
                    prev_hash=last_hash,
                    anchor_hash=anchor_hash if is_fresh_chain else None,
                    request_id=getattr(action, "request_id", None),
                )
            else:
                rec = build_record(
                    action,
                    result,
                    parent_decision=last_decision_id,
                    prev_hash=last_hash,
                    anchor_hash=anchor_hash if is_fresh_chain else None,
                    request_id=getattr(action, "request_id", None),
                )
            env_dict = (
                self.signer.sign_record(rec).to_dict()
                if self.signer is not None
                else None
            )
            if self.store.append_atomic(rec, envelope=env_dict):
                if env_dict is not None:
                    self.envelopes[rec.record_hash] = env_dict
                # Deliberately do NOT call self.graph.add(rec) here.
                # In multi-writer mode, this recorder's local in-memory
                # graph cannot be kept consistent with what OTHER
                # writers have committed -- it would need its own
                # synchronization, which is out of scope. The store is
                # the source of truth; call restore_chains() or
                # store.load_graph() to get a fresh, correct view when
                # you need one (e.g. for verify_chain or queries).
                return rec
            # lost the race -- brief randomized backoff before retrying
            # so competing writers don't immediately re-collide in
            # lockstep (a thundering herd), then re-read the updated
            # chain head
            time.sleep(random.uniform(0.001, 0.01) * (attempt + 1))
        raise RuntimeError(
            f"append_atomic failed {max_retries} times for agent "
            f"{action.agent_id!r} -- unexpectedly high write contention"
        )

    def report_outcome(
        self,
        decision_id: str,
        status: str,
        detail: str = "",
    ) -> ExecutionEvent:
        """Executor feedback: append an ExecutionEvent anchored to the
        decision it reports on. Does NOT touch the decision chain —
        events chain off their decision's hash, not the agent chain."""
        if self.multi_writer_safe:
            # The in-memory graph is deliberately unpopulated in this
            # mode; the store is authoritative (audit set 4). The
            # graph.get path would KeyError on every outcome here.
            d = self.store.get_decision(decision_id)
            if d is None:
                raise KeyError(decision_id)
            event = build_execution_event(
                agent_id=d["agent_id"],
                decision_id=d["decision_id"],
                decision_hash=d["record_hash"],
                status=status,
                detail=detail,
            )
            # UNIQUE(decision_ref) makes duplicate outcomes a
            # database-level ValueError across processes
            self.store.append(event)
            return event
        decision = self.graph.get(decision_id)
        event = build_execution_event(
            agent_id=decision.agent_id,
            decision_id=decision.decision_id,
            decision_hash=decision.record_hash,
            status=status,
            detail=detail,
        )
        if self.store is not None:
            self.store.append(event)  # durability + DB uniqueness first
        self.graph.add_execution(event)
        return event
