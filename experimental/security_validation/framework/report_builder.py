"""
Report Builder.

Converts AttackResult into Schema v1.1 BenchmarkReport.
"""

from __future__ import annotations

from agent_dna.security_validation.framework.attack_result import AttackResult
from agent_dna.security_validation.schema.report_v1_1 import (
    Actor,
    AttackInfo,
    BenchmarkInfo,
    BenchmarkReport,
    Decision,
)


class ReportBuilder:
    """Build Schema v1.1 benchmark reports."""

    def build(self, result: AttackResult) -> BenchmarkReport:

        benchmark = BenchmarkInfo()

        attack = AttackInfo(
            id=result.attack_name.lower().replace(" ", "_"),
            name=result.attack_name,
            severity=result.metadata.get("severity", "unknown"),
            frameworks=result.metadata.get("frameworks", {}),
        )

        attacker = Actor(
            agent=result.metadata.get("attacker", "unknown"),
            agents=result.metadata.get("attacker_agents", []),
            role="attacker",
        )

        target = Actor(
            agent=result.metadata.get("target", "runtime"),
            role="target",
        )

        decision = Decision(
            status=result.status,
            security_score=result.security_score,
            reason=result.reason,
        )

        return BenchmarkReport(
            benchmark=benchmark,
            attack=attack,
            attacker=attacker,
            target=target,
            decision=decision,
            evidence=result.evidence,
            metrics=result.metrics,
            metadata=result.metadata,
        )
