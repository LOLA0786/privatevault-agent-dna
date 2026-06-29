"""One execution = one directed multi-agent interaction graph G = (V, E).

This is the object the invariant learners train on and the runtime validates.
It stays cheap: no numpy, no networkx. Just enough graph algebra to support
topology / temporal / authority reasoning.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Iterator

from .events import InteractionEvent


class InteractionGraph:
    def __init__(self, execution_id: str) -> None:
        self.execution_id = execution_id
        self.events: list[InteractionEvent] = []
        self._roles: dict[str, str] = {}            # agent -> role
        self._first_seen: dict[str, float] = {}     # agent -> earliest ts

    # ---- construction -----------------------------------------------------
    def add_event(self, event: InteractionEvent) -> "InteractionGraph":
        if event.execution_id != self.execution_id:
            raise ValueError(
                f"event execution_id {event.execution_id!r} does not match "
                f"graph {self.execution_id!r}"
            )
        self.events.append(event)
        for agent, role in ((event.source, event.source_role),
                            (event.target, event.target_role)):
            # first non-unknown role wins; never downgrade a known role
            if role != "unknown" or agent not in self._roles:
                self._roles[agent] = role
            prev = self._first_seen.get(agent)
            if prev is None or event.timestamp < prev:
                self._first_seen[agent] = event.timestamp
        return self

    def extend(self, events: Iterable[InteractionEvent]) -> "InteractionGraph":
        for e in events:
            self.add_event(e)
        return self

    # ---- topology ---------------------------------------------------------
    @property
    def nodes(self) -> set[str]:
        return set(self._roles)

    @property
    def edges(self) -> set[tuple[str, str]]:
        return {e.edge() for e in self.events}

    @property
    def role_edges(self) -> set[tuple[str, str]]:
        return {e.role_edge() for e in self.events}

    @property
    def roles(self) -> set[str]:
        return set(self._roles.values())

    def role_of(self, agent: str) -> str:
        return self._roles.get(agent, "unknown")

    # ---- temporal ---------------------------------------------------------
    def first_seen(self, agent: str) -> float:
        return self._first_seen[agent]

    def role_first_seen(self) -> dict[str, float]:
        """Earliest timestamp at which each role appears in this execution."""
        out: dict[str, float] = {}
        for agent, ts in self._first_seen.items():
            role = self._roles.get(agent, "unknown")
            if role not in out or ts < out[role]:
                out[role] = ts
        return out

    def role_precedes(self, role_a: str, role_b: str) -> bool | None:
        """True if role_a first appears strictly before role_b in this run.
        None if either role is absent."""
        fs = self.role_first_seen()
        if role_a not in fs or role_b not in fs:
            return None
        return fs[role_a] < fs[role_b]

    # ---- misc -------------------------------------------------------------
    def ordered_events(self) -> list[InteractionEvent]:
        return sorted(self.events, key=lambda e: e.timestamp)

    def __len__(self) -> int:
        return len(self.events)

    def __iter__(self) -> Iterator[InteractionEvent]:
        return iter(self.ordered_events())

    def __repr__(self) -> str:
        return (f"InteractionGraph(execution_id={self.execution_id!r}, "
                f"nodes={len(self.nodes)}, edges={len(self.edges)})")
