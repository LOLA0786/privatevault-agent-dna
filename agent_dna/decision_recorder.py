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
    ) -> None:
        self.graph = graph if graph is not None else DecisionGraph()
        self.store = store
        self.signer = signer
        self.envelopes: Dict[str, dict] = {}   # record_hash -> envelope
        self._chains: Dict[str, _ChainState] = {}

    def record(
        self,
        action: AgentAction,
        result: DecisionResult,
    ) -> DecisionRecord:
        chain = self._chains.setdefault(action.agent_id, _ChainState())

        rec = build_record(
            action,
            result,
            parent_decision=chain.last_decision_id,
            prev_hash=chain.last_hash,
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
