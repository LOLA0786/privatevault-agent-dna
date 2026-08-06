"""
OPA Adapter + DecisionEngine Integration Demo.
Shows agent_dna/adapters_policy/opa.py in action
without modifying existing decision.py or consensus code.
"""

from agent_dna import AgentAction, DecisionEngine
from agent_dna.adapters_policy.opa import OPAPolicyAdapter
from agent_dna.observability.logger import get_logger

logger = get_logger("pv_opa_demo")


def demo():
    class _StubScorer:
        def score(self, action, prev_capability=None):
            from agent_dna.advisory import AdvisorySignal, Severity

            return AdvisorySignal(
                agent_id=action.agent_id,
                capability=action.capability,
                drift_score=0.0,
                severity=Severity.INFO,
                reasons=[],
            )

    adapter = OPAPolicyAdapter(
        endpoint="http://localhost:8181", default_decision="block"
    )
    # scorer required: without one the engine fail-closed on the
    # missing scorer BEFORE the policy level, so this demo blocked for
    # the wrong reason and never exercised OPA at all (audit-era bug)
    engine = DecisionEngine(scorer=_StubScorer(), drift_threshold=0.8, policy=adapter)

    # Agent attempts capability; adapter checks against OPA policy
    # (If OPA is offline the adapter RAISES PolicyUnavailableError
    #  and the engine fails closed: BLOCK / engine_fault -- P0-1)
    action = AgentAction(
        "finance-agent-01",
        "payments.initiate_wire",
        timestamp=1.0,
        arguments={"amount": 25000},
    )

    result = engine.decide(action)
    logger.info(
        "opa_decision",
        extra={
            "agent": action.agent_id,
            "capability": action.capability,
            "verdict": result.decision.value,
            "triggered_by": result.triggered_by,
            "adapter": "opa",
            "default_fallback": adapter.default_decision,
        },
    )
    print(
        f"OPA Adapter Result: {str(result.decision).upper()} "
        f"(trigger={result.triggered_by}, reason={result.reason})"
    )


if __name__ == "__main__":
    demo()
