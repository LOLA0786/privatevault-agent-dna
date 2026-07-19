"""
Framework Benchmark Runner.

Uses the new Registry + Pipeline while leaving the
legacy orchestrator untouched.
"""

from __future__ import annotations

from typing import List

from agent_dna.security_validation.framework.attack_result import AttackResult
from agent_dna.security_validation.framework.pipeline import Pipeline
from agent_dna.security_validation.framework.registry import Registry


class BenchmarkRunner:
    def __init__(self):
        self.registry = Registry()
        self.pipeline = Pipeline()

    def discover(self):
        self.registry.discover()
        return self.registry.names()

    def execute(self) -> List:

        reports = []

        for attack_cls in self.registry.classes():

            attack = attack_cls()

            result = attack.run(target_agent="demo-target-agent")

            attack_result = AttackResult(
                attack_name=attack_cls.__name__,
                status=result.get("status", "unknown"),
                security_score=float(result.get("security_score", 0)),
                reason=result.get("reason", ""),
                evidence=result.get("evidence", []),
                metrics=result.get("metrics", {}),
                metadata=result,
                raw_result=result,
            )

            report = self.pipeline.process(attack_result)

            reports.append(report)

        return reports
