"""Runtime entrypoint for the Decision Security Runtime.

Wraps a trained :class:`InvariantEngine` and exposes the call the enforcement
path actually makes: hand it the events of an in-flight (or completed)
execution, get back ALLOW / REVIEW / BLOCK plus a human-readable explanation.

Train once from a corpus, then validate live:

    validator = RuntimeValidator.from_corpus(known_good_events)
    verdict = validator.validate_events(live_events)
    if verdict.verdict is Verdict.BLOCK:
        ...
"""
from __future__ import annotations

from typing import Iterable

from .authority import AuthorityInvariant
from .base import Verdict
from .events import InteractionEvent
from .graph_builder import GraphBuilder
from .interaction_graph import InteractionGraph
from .invariant_engine import EngineVerdict, InvariantEngine
from .temporal import TemporalInvariant
from .topology import TopologyInvariant


def default_engine() -> InvariantEngine:
    """The Phase-1 invariant stack: topology + temporal + authority."""
    return InvariantEngine(
        invariants=[
            TopologyInvariant(),
            TemporalInvariant(),
            AuthorityInvariant(),
        ]
    )


class RuntimeValidator:
    def __init__(self, engine: InvariantEngine | None = None) -> None:
        self.engine = engine or default_engine()

    # ---- training ---------------------------------------------------------
    def learn(self, graphs: list[InteractionGraph]) -> "RuntimeValidator":
        self.engine.learn(graphs)
        return self

    @classmethod
    def from_corpus(cls, events: Iterable[InteractionEvent],
                    engine: InvariantEngine | None = None) -> "RuntimeValidator":
        builder = GraphBuilder().ingest_many(events)
        validator = cls(engine)
        validator.learn(builder.build_all())
        return validator

    @classmethod
    def from_graphs(cls, graphs: list[InteractionGraph],
                    engine: InvariantEngine | None = None) -> "RuntimeValidator":
        return cls(engine).learn(graphs)

    # ---- validation -------------------------------------------------------
    def validate(self, graph: InteractionGraph) -> EngineVerdict:
        return self.engine.evaluate(graph)

    def validate_events(self, events: Iterable[InteractionEvent]) -> EngineVerdict:
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

    # convenience for the hot path
    def is_allowed(self, events: Iterable[InteractionEvent]) -> bool:
        return self.validate_events(events).verdict is Verdict.ALLOW
