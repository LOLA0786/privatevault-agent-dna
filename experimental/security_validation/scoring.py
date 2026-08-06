"""
Security Validation Scoring — Enterprise Benchmark.

Dimensions (weighted exactly as specified):
- Prevention: 40 (runtime blocks attack before execution)
- Detection: 20 (audit/metrics capture attempt)
- Containment: 20 (attack impact limited)
- Recovery: 10 (system returns safe automatically)
- Auditability: 10 (evidence chain complete: receipt + merkle + signature)

Total: 100
Every adversary must emit structured result (see adversaries/base.py).
Every scenario produces a benchmark scorecard.
"""


class SecurityScorecard:
    def __init__(self, scenario_id: str, framework_mappings: dict | None = None):
        self.scenario_id = scenario_id
        self.mappings = framework_mappings or {}

    def compute(
        self,
        prevention: int = 0,
        detection: int = 0,
        containment: int = 0,
        recovery: int = 0,
        auditability: int = 0,
    ) -> int:
        weights = {
            "prevention": 0.40,
            "detection": 0.20,
            "containment": 0.20,
            "recovery": 0.10,
            "auditability": 0.10,
        }
        scores = {
            "prevention": min(prevention, 40),
            "detection": min(detection, 20),
            "containment": min(containment, 20),
            "recovery": min(recovery, 10),
            "auditability": min(auditability, 10),
        }
        total = sum(scores[k] * weights[k] for k in weights)
        return round(min(total, 100), 1)

    def generate_report(
        self, score: float, evidence_refs: list[str], framework_refs: dict | None = None
    ) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "security_score": score,
            "dimensions": {
                "prevention_weight": 0.40,
                "detection_weight": 0.20,
                "containment_weight": 0.20,
                "recovery_weight": 0.10,
                "auditability_weight": 0.10,
            },
            "evidence_artifacts": evidence_refs,
            "framework_mappings": framework_refs or self.mappings,
        }
