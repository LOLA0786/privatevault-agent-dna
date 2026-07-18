from __future__ import annotations

from statistics import mean

from .results import AttackResult


class Metrics:

    @staticmethod
    def prevention_rate(results: list[AttackResult]) -> float:
        if not results:
            return 0.0

        prevented = sum(r.status == "BLOCKED" for r in results)

        return prevented / len(results)

    @staticmethod
    def average_latency(results: list[AttackResult]) -> float:
        if not results:
            return 0.0

        return mean(r.latency_ms for r in results)

    @staticmethod
    def runtime_security_score(results: list[AttackResult]) -> float:
        if not results:
            return 0.0

        return mean(r.score for r in results)
