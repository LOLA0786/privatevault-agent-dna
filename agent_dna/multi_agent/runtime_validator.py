"""Runtime entrypoint for the Decision Security Runtime."""
from __future__ import annotations

from typing import Iterable

from .authority import AuthorityInvariant
from .base import Verdict
from .consensus import ConsensusInvariant
from .events import InteractionEvent
from .graph_builder import GraphBuilder
from .interaction_graph import InteractionGraph
from .intent import IntentInvariant
from .invariant_engine import EngineVerdict, InvariantEngine
from .temporal import TemporalInvariant
from .topology import TopologyInvariant
from .world_state import WorldStateInvariant


def default_engine() -> InvariantEngine:
    return InvariantEngine(
        invariants=[
            TopologyInvariant(),
            TemporalInvariant(),
            AuthorityInvariant(),
            ConsensusInvariant(),
            IntentInvariant(),
            WorldStateInvariant(),
        ]
    )


class RuntimeValidator:
    def __init__(self, engine: InvariantEngine | None = None) -> None:
        self.engine = engine or default_engine()

    def learn(self, graphs: list[InteractionGraph]) -> "RuntimeValidator":
        self.engine.learn(graphs)
        return self

    @classmethod
    def from_corpus(
        cls,
        events: Iterable[InteractionEvent],
        engine: InvariantEngine | None = None,
    ) -> "RuntimeValidator":
        builder = GraphBuilder().ingest_many(events)
        validator = cls(engine)
        validator.learn(builder.build_all())
        return validator

    @classmethod
    def from_graphs(
        cls,
        graphs: list[InteractionGraph],
        engine: InvariantEngine | None = None,
    ) -> "RuntimeValidator":
        return cls(engine).learn(graphs)

    def validate(self, graph: InteractionGraph) -> EngineVerdict:
        return self.engine.evaluate(graph)

    def validate_events(
        self,
        events: Iterable[InteractionEvent],
    ) -> EngineVerdict:
        events = list(events)

        if not events:
            raise ValueError("cannot validate an empty execution")

        exec_ids = {e.execution_id for e in events}

        if len(exec_ids) != 1:
            raise ValueError(
                f"validate_events expects a single execution, got {exec_ids}"
            )

        graph = InteractionGraph(events[0].execution_id).extend(events)

        return self.validate(graph)

    def is_allowed(self, events: Iterable[InteractionEvent]) -> bool:
        return self.validate_events(events).verdict is Verdict.ALLOW
