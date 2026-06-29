"""Combine every invariant family into a single verdict for one execution.

Aggregation policy (deterministic, explainable):

  * Any HARD breach (authority / temporal) -> BLOCK.
  * Else combined soft severity >= block_threshold -> BLOCK.
  * Else combined soft severity >= review_threshold -> REVIEW.
  * Else -> ALLOW.

Soft severities combine via noisy-OR so multiple weak signals accumulate
toward review/block without ever exceeding 1.0.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .base import Invariant, InvariantResult, Verdict
from .interaction_graph import InteractionGraph


@dataclass
class EngineVerdict:
    verdict: Verdict
    score: float                      # aggregated soft severity in [0,1]
    results: list[InvariantResult] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW

    def explain(self) -> str:
        lines = [f"VERDICT: {self.verdict.value}  (score={self.score:.3f})"]
        for r in self.results:
            status = "ok" if r.passed else ("HARD" if r.hard else "soft")
            lines.append(f"  [{status:>4}] {r.name}: severity={r.severity:.2f}")
            for v in r.violations:
                lines.append(f"          - {v}")
        return "\n".join(lines)


class InvariantEngine:
    def __init__(self, invariants: list[Invariant] | None = None,
                block_threshold: float = 0.80,
                review_threshold: float = 0.05) -> None:
        self.invariants: list[Invariant] = invariants or []
        self.block_threshold = block_threshold
        self.review_threshold = review_threshold
        self._learned = False

    def add(self, invariant: Invariant) -> "InvariantEngine":
        self.invariants.append(invariant)
        return self

    def learn(self, graphs: list[InteractionGraph]) -> "InvariantEngine":
        for inv in self.invariants:
            inv.learn(graphs)
        self._learned = True
        return self

    @staticmethod
    def _noisy_or(severities: list[float]) -> float:
        prod = 1.0
        for s in severities:
            prod *= (1.0 - max(0.0, min(1.0, s)))
        return 1.0 - prod

    def evaluate(self, graph: InteractionGraph) -> EngineVerdict:
        if not self._learned:
            raise RuntimeError("InvariantEngine.evaluate called before learn()")

        results = [inv.check(graph) for inv in self.invariants]
        hard_breaches = [r for r in results if r.hard and not r.passed]
        soft_score = self._noisy_or([r.severity for r in results if not r.hard])

        reasons: list[str] = []
        if hard_breaches:
            verdict = Verdict.BLOCK
            for r in hard_breaches:
                reasons.extend(r.violations)
        elif soft_score >= self.block_threshold:
            verdict = Verdict.BLOCK
            reasons.append(f"aggregate soft severity {soft_score:.2f} "
                        f">= block threshold {self.block_threshold:.2f}")
        elif soft_score >= self.review_threshold:
            verdict = Verdict.REVIEW
            for r in results:
                if not r.passed:
                    reasons.extend(r.violations)
        else:
            verdict = Verdict.ALLOW

        return EngineVerdict(verdict=verdict, score=soft_score,
                            results=results, reasons=reasons)

    def describe(self) -> dict:
        return {
            "block_threshold": self.block_threshold,
            "review_threshold": self.review_threshold,
            "invariants": [inv.describe() for inv in self.invariants],
        }
