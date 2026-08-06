"""
DecisionGraph — append-only, queryable store of DecisionRecords.

Deliberately separate from multi_agent.interaction_graph:
  * InteractionGraph models WHO talks to WHOM (agent/role topology
    per execution) — the substrate CABI invariants learn on.
  * DecisionGraph models WHAT was decided AFTER WHAT (per-agent
    decision lineage) — the substrate audit, replay, and the Query
    API stand on.

Same zero-dependency discipline as interaction_graph: no numpy,
no networkx.

Today each agent's records form a linear hash chain (parent =
previous decision for that agent). The structure is stored as a
general parent -> children mapping so delegation (true branching)
can land later without a storage migration. Until branching exists,
do not call this a DAG in public claims.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator

from .decision_record import DecisionRecord
from .execution_record import ExecutionEvent


class DecisionGraph:
    def __init__(self) -> None:
        self._records: dict[str, DecisionRecord] = {}  # decision_id -> record
        self._order: list[str] = []  # insertion order
        self._children: dict[str, list[str]] = defaultdict(list)
        self._by_agent: dict[str, list[str]] = defaultdict(list)
        self._by_capability: dict[str, list[str]] = defaultdict(list)
        self._by_decision: dict[str, list[str]] = defaultdict(list)
        self._by_trigger: dict[str, list[str]] = defaultdict(list)
        self._executions: dict[str, ExecutionEvent] = {}  # decision_id -> event

    # ---- construction ---------------------------------------------------

    def add(self, record: DecisionRecord) -> DecisionGraph:
        if not record.verify():
            raise ValueError(
                f"record {record.decision_id} is unsealed or tampered; "
                "refusing to store"
            )
        if record.decision_id in self._records:
            raise ValueError(f"duplicate decision_id {record.decision_id}")
        if (
            record.parent_decision is not None
            and record.parent_decision not in self._records
        ):
            raise ValueError(
                f"parent {record.parent_decision} not in graph — "
                "records must be added in causal order"
            )

        self._records[record.decision_id] = record
        self._order.append(record.decision_id)
        if record.parent_decision is not None:
            self._children[record.parent_decision].append(record.decision_id)

        self._by_agent[record.agent_id].append(record.decision_id)
        self._by_capability[record.capability].append(record.decision_id)
        self._by_decision[record.decision].append(record.decision_id)
        self._by_trigger[record.triggered_by].append(record.decision_id)
        return self

    def add_execution(self, event: ExecutionEvent) -> DecisionGraph:
        if not event.verify():
            raise ValueError(
                f"execution event {event.event_id} is unsealed or tampered"
            )
        if event.decision_ref not in self._records:
            raise ValueError(
                f"execution event references unknown decision {event.decision_ref}"
            )
        decision = self._records[event.decision_ref]
        if event.prev_hash != decision.record_hash:
            raise ValueError(
                f"execution event anchor mismatch: prev_hash does not "
                f"equal decision {event.decision_ref} record_hash"
            )
        if event.decision_ref in self._executions:
            raise ValueError(
                f"decision {event.decision_ref} already has an execution event"
            )
        self._executions[event.decision_ref] = event
        return self

    def outcome_of(self, decision_id: str) -> str:
        ev = self._executions.get(decision_id)
        return ev.status if ev is not None else "pending"

    def find_divergent(self) -> list[DecisionRecord]:
        """Decisions the runtime BLOCKed that the executor reports as
        executed anyway — enforcement divergence."""
        out = []
        for did, ev in self._executions.items():
            rec = self._records[did]
            if rec.decision == "block" and ev.status == "ok":
                out.append(rec)
        return out

    # ---- lineage ----------------------------------------------------------

    def get(self, decision_id: str) -> DecisionRecord:
        return self._records[decision_id]

    def parent(self, decision_id: str) -> DecisionRecord | None:
        pid = self._records[decision_id].parent_decision
        return self._records[pid] if pid is not None else None

    def children(self, decision_id: str) -> list[DecisionRecord]:
        return [self._records[c] for c in self._children.get(decision_id, [])]

    def lineage(self, decision_id: str) -> list[DecisionRecord]:
        """Root-to-node path: every decision that led here."""
        path: list[DecisionRecord] = []
        cur: str | None = decision_id
        while cur is not None:
            rec = self._records[cur]
            path.append(rec)
            cur = rec.parent_decision
        path.reverse()
        return path

    def descendants(self, decision_id: str) -> list[DecisionRecord]:
        """Everything downstream of a decision (replay_after substrate)."""
        out: list[DecisionRecord] = []
        stack = list(self._children.get(decision_id, []))
        while stack:
            cid = stack.pop()
            out.append(self._records[cid])
            stack.extend(self._children.get(cid, []))
        out.sort(key=lambda r: r.timestamp)
        return out

    # ---- queries ------------------------------------------------------------

    def find_by_agent(self, agent_id: str) -> list[DecisionRecord]:
        return [self._records[i] for i in self._by_agent.get(agent_id, [])]

    def find_by_capability(self, capability: str) -> list[DecisionRecord]:
        return [self._records[i] for i in self._by_capability.get(capability, [])]

    def find_blocked(self) -> list[DecisionRecord]:
        return [self._records[i] for i in self._by_decision.get("block", [])]

    def find_requires_approval(self) -> list[DecisionRecord]:
        return [self._records[i] for i in self._by_decision.get("require_approval", [])]

    def find_by_trigger(self, triggered_by: str) -> list[DecisionRecord]:
        return [self._records[i] for i in self._by_trigger.get(triggered_by, [])]

    # ---- integrity ---------------------------------------------------------

    def verify_chain(self, agent_id: str) -> bool:
        """Walk one agent's records in insertion order and confirm the
        hash chain is intact from the second record onward: each
        record verifies individually and its prev_hash equals the
        previous record's record_hash.

        The first record's prev_hash is accepted as given -- either
        GENESIS_HASH (unanchored chain) or an external provenance
        anchor (see decision_record.build_record's anchor_hash). This
        method verifies INTERNAL chain continuity only; it cannot
        independently confirm an anchor corresponds to a real
        upstream artifact -- that requires checking against the
        external provenance source separately."""
        ids = self._by_agent.get(agent_id, [])
        if not ids:
            return True
        prev = None
        for i in ids:
            rec = self._records[i]
            if not rec.verify():
                return False
            if prev is None:
                prev = rec.prev_hash
            elif rec.prev_hash != prev:
                return False
            prev = rec.record_hash
        return True

    def verify_all(self) -> dict[str, bool]:
        return {a: self.verify_chain(a) for a in self._by_agent}

    # ---- misc ---------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self) -> Iterator[DecisionRecord]:
        return iter(self._records[i] for i in self._order)

    def __repr__(self) -> str:
        return f"DecisionGraph(records={len(self)}, agents={len(self._by_agent)})"
