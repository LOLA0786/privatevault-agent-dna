"""Cross-Agent Behavioral Invariants (CABI) -- Agent DNA v2.

Learn the behavioral DNA of an entire society of agents, then enforce it at
runtime. Where v1 Agent DNA answers "did Agent A behave strangely?", CABI
answers "did the collective decision process violate the learned
organizational DNA?".

Phase 1 invariant families: topology, temporal, authority.
"""
from __future__ import annotations

from .authority import AuthorityInvariant
from .base import Invariant, InvariantResult, Verdict
from .consensus import ConsensusInvariant
from .events import InteractionEvent
from .graph_builder import GraphBuilder
from .interaction_graph import InteractionGraph
from .invariant_engine import EngineVerdict, InvariantEngine
from .runtime_validator import RuntimeValidator, default_engine
from .temporal import TemporalInvariant
from .topology import TopologyInvariant

__all__ = [
    "InteractionEvent",
    "InteractionGraph",
    "GraphBuilder",
    "Invariant",
    "InvariantResult",
    "Verdict",
    "TopologyInvariant",
    "TemporalInvariant",
    "AuthorityInvariant",
    "ConsensusInvariant",
    "InvariantEngine",
    "EngineVerdict",
    "RuntimeValidator",
    "default_engine",
]

__version__ = "0.1.0"
