"""
Attack Orchestrator — Runs adversarial scenarios and collects evidence.

Produces structured results for every adversary execution.
Links results to audit artifacts (receipt hash, merkle root, policy version).
Compatible with CI/CD pipeline (security_validation/ci_integration.md).
"""
from typing import List, Dict, Optional
from .adversaries.base import BaseAdversary
from .scoring import SecurityScorecard
from .framework.discovery.loader import discover


class AttackOrchestrator:
    """
    Execute one or many adversaries against agent runtime.
    Collect structured evidence for benchmark reporting.
    """
    def __init__(self, runtime_target: Optional[str] = None):
        self.runtime_target = runtime_target or "agent_dna.decision"
        self.results: List[Dict] = []

        self.discovered_adversaries = [
            cls for cls in discover()
        ]

    def run_adversary(self, adversary: BaseAdversary, target_agent: str) -> Dict:
        result_dict = adversary.run(target_agent=target_agent)
        scorecard = SecurityScorecard(
            scenario_id=adversary.attack_id,
            framework_mappings=adversary.framework_mappings,
        )
        score = scorecard.compute(
            prevention=result_dict.get("prevention_score", 30),
            detection=result_dict.get("detection_score", 15),
            containment=result_dict.get("containment_score", 15),
            recovery=result_dict.get("recovery_score", 8),
            auditability=result_dict.get("auditability_score", 10),
        )
        full_result = {
            "adversary_id": adversary.attack_id,
            "structured_result": result_dict,
            "security_score": score,
            "evidence_refs": result_dict.get("evidence_artifacts", []),
        }
        self.results.append(full_result)
        return full_result

    def benchmark_summary(self, framework_refs: Optional[Dict] = None) -> Dict:
        scores = [r["security_score"] for r in self.results]
        return {
            "runtime_target": self.runtime_target,
            "adversaries_executed": len(self.results),
            "average_score": sum(scores) / max(len(scores), 1),
            "min_score": min(scores) if scores else 0,
            "max_score": max(scores) if scores else 0,
            "results": self.results,
        }


    def list_adversaries(self):
        """
        Return discovered adversary classes.
        """
        return self.discovered_adversaries

    def run_all(self, target_agent: str):
        """
        Execute every discovered adversary.
        """
        for adversary_cls in self.discovered_adversaries:

            try:
                adversary = adversary_cls()

            except TypeError:
                # adversary requires constructor arguments
                continue

            self.run_adversary(
                adversary=adversary,
                target_agent=target_agent,
            )

        return self.benchmark_summary()
