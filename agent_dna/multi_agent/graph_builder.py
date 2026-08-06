"""Maintain evolving multi-agent state: group a flat event stream into
per-execution :class:`InteractionGraph` objects.

In production the builder is fed live runtime events; in training it is fed a
recorded corpus. Same code path either way.
"""

from __future__ import annotations

from collections.abc import Iterable

from .events import InteractionEvent
from .interaction_graph import InteractionGraph


class GraphBuilder:
    def __init__(self) -> None:
        self._graphs: dict[str, InteractionGraph] = {}

    def ingest(self, event: InteractionEvent) -> InteractionGraph:
        g = self._graphs.get(event.execution_id)
        if g is None:
            g = InteractionGraph(event.execution_id)
            self._graphs[event.execution_id] = g
        g.add_event(event)
        return g

    def ingest_many(self, events: Iterable[InteractionEvent]) -> GraphBuilder:
        for e in events:
            self.ingest(e)
        return self

    def get(self, execution_id: str) -> InteractionGraph:
        return self._graphs[execution_id]

    def build_all(self) -> list[InteractionGraph]:
        return list(self._graphs.values())

    def reset(self) -> None:
        self._graphs.clear()

    def __len__(self) -> int:
        return len(self._graphs)
