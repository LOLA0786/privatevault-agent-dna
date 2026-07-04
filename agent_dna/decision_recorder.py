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
    ) -> None:
        self.graph = graph if graph is not None else DecisionGraph()
        self.store = store
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

        chain.last_decision_id = rec.decision_id
        chain.last_hash = rec.record_hash
        return rec
