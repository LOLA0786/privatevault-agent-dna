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
from dataclasses import dataclass
from typing import Dict, Optional

from .decision import DecisionResult
from .decision_graph import DecisionGraph
from .decision_record import GENESIS_HASH, DecisionRecord, build_record
from .execution_record import ExecutionEvent, build_execution_event
from .trace import AgentAction


@dataclass
class _ChainState:
    last_decision_id: Optional[str] = None
    last_hash: str = GENESIS_HASH


class DecisionRecorder:
    def __init__(
        self,
        graph: Optional[DecisionGraph] = None,
        store=None,                       # optional DecisionStore
        signer=None,                      # optional ReceiptSigner
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
        self.envelopes: Dict[str, dict] = {}   # record_hash -> envelope
        self._chains: Dict[str, _ChainState] = {}
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
        anchor_hash: Optional[str] = None,
    ) -> DecisionRecord:
        if self.multi_writer_safe:
            return self._record_multi_writer_safe(action, result, anchor_hash)
        is_fresh_chain = action.agent_id not in self._chains
        chain = self._chains.setdefault(action.agent_id, _ChainState())

        rec = build_record(
            action,
            result,
            parent_decision=chain.last_decision_id,
            prev_hash=chain.last_hash,
            anchor_hash=anchor_hash if is_fresh_chain else None,
        )
        self.graph.add(rec)
        if self.store is not None:
            self.store.append(rec)
        if self.signer is not None:
            env = self.signer.sign_record(rec)
            self.envelopes[rec.record_hash] = env.to_dict()

        chain.last_decision_id = rec.decision_id
        chain.last_hash = rec.record_hash
        return rec

    def _record_multi_writer_safe(
        self,
        action: AgentAction,
        result: DecisionResult,
        anchor_hash: Optional[str] = None,
        max_retries: int = 20,
    ) -> DecisionRecord:
        """Chain head is read fresh from the store on every call --
        never trusts in-memory state, since another process may have
        written since this process last checked. On a lost race
        (store.append_atomic returns False because another writer
        claimed this agent's chain from the same prev_hash first),
        re-reads the now-updated head and retries."""
        for attempt in range(max_retries):
            last_decision_id, last_hash = self.store.get_chain_head(
                action.agent_id
            )
            is_fresh_chain = last_decision_id is None
            rec = build_record(
                action,
                result,
                parent_decision=last_decision_id,
                prev_hash=last_hash,
                anchor_hash=anchor_hash if is_fresh_chain else None,
            )
            if self.store.append_atomic(rec):
                # Deliberately do NOT call self.graph.add(rec) here.
                # In multi-writer mode, this recorder's local in-memory
                # graph cannot be kept consistent with what OTHER
                # writers have committed -- it would need its own
                # synchronization, which is out of scope. The store is
                # the source of truth; call restore_chains() or
                # store.load_graph() to get a fresh, correct view when
                # you need one (e.g. for verify_chain or queries).
                if self.signer is not None:
                    env = self.signer.sign_record(rec)
                    self.envelopes[rec.record_hash] = env.to_dict()
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
        decision = self.graph.get(decision_id)
        event = build_execution_event(
            agent_id=decision.agent_id,
            decision_id=decision.decision_id,
            decision_hash=decision.record_hash,
            status=status,
            detail=detail,
        )
        self.graph.add_execution(event)
        if self.store is not None:
            self.store.append(event)
        return event
