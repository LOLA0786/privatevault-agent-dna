"""Trust Behavioral Invariant."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from .interaction_graph import InteractionGraph


@dataclass(slots=True)
class TrustResult:
    severity: float
    reasons: list[str]
    hard: bool = False


class TrustInvariant:
    """Learns expected trust relationships between agent pairs.

    NOT WIRED. This invariant iterates graph.edges expecting edge
    OBJECTS with .source/.target/.trust_score, but
    InteractionGraph.edges is a set[tuple[str, str]] -- (source, target)
    agent-id pairs with no per-edge trust value. So fit()/validate()
    raise on a real graph, and nothing in the serving path calls it.

    The project's actual trust data is per-AGENT
    (agent_dna.consensus.TrustRegistry: agent_id -> score in [0,1]),
    not per-EDGE. Wiring this correctly requires a modelling decision
    -- how per-agent trust maps to a per-pair edge check -- that is
    deliberately deferred rather than guessed. Tracked as a roadmap
    item; pinned by tests/test_trust_invariant.py.
    """

    name = "trust"

    def __init__(self,
                 review_margin: float = 0.10,
                 block_margin: float = 0.30):
        self.review_margin = review_margin
        self.block_margin = block_margin
        self.minimum_trust = {}

    def fit(self, graphs: list[InteractionGraph]) -> None:
        values = defaultdict(list)

        for graph in graphs:
            for edge in graph.edges:
                trust = getattr(edge, "trust_score", 1.0)
                values[(edge.source, edge.target)].append(trust)

        self.minimum_trust = {
            pair: min(scores)
            for pair, scores in values.items()
        }

    def validate(self, graph: InteractionGraph) -> TrustResult:
        severity = 0.0
        reasons = []
        hard = False

        for edge in graph.edges:
            pair = (edge.source, edge.target)

            if pair not in self.minimum_trust:
                continue

            expected = self.minimum_trust[pair]
            observed = getattr(edge, "trust_score", 1.0)

            delta = expected - observed

            if delta >= self.block_margin:
                hard = True
                severity = 1.0
                reasons.append(
                    f"trust breach: {edge.source} -> {edge.target} "
                    f"(expected >= {expected:.2f}, observed {observed:.2f})"
                )

            elif delta >= self.review_margin:
                severity = max(severity, 0.40)
                reasons.append(
                    f"trust degradation: {edge.source} -> {edge.target} "
                    f"(expected >= {expected:.2f}, observed {observed:.2f})"
                )

        return TrustResult(
            severity=severity,
            reasons=reasons,
            hard=hard,
        )

    def describe(self):
        return {
            "name": self.name,
            "trusted_edges": len(self.minimum_trust),
        }

