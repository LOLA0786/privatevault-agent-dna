"""
Decision Graph demo: full pipeline on a compromised trace.

    AgentAction -> DecisionEngine -> RuntimeMonitor
                        |
                  DecisionRecorder
                        |
                  DecisionGraph  (queryable, hash-chained, tamper-evident)

Reuses the trained scorer and compromised trace from runtime_demo.
"""

from agent_dna.decision import DecisionEngine
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.runtime import RuntimeMonitor

from runtime_demo import banner, synthetic_compromised_trace, train


def main():
    scorer = train()
    recorder = DecisionRecorder()
    engine = DecisionEngine(scorer=scorer)
    monitor = RuntimeMonitor(engine, recorder=recorder)

    banner("LIVE STREAM (recorded)")
    for action in synthetic_compromised_trace().actions:
        result = monitor.process(action)
        print(
            f"{action.capability:<28}"
            f" -> {result.decision.value.upper():<17}"
            f" trigger={result.triggered_by}"
        )

    g = recorder.graph

    banner("QUERY: decisions requiring approval")
    for r in g.find_requires_approval():
        print(f"{r.capability:<28} reason: {r.reason}")

    banner("LINEAGE of last decision")
    last = list(g)[-1]
    for step in g.lineage(last.decision_id):
        print(
            f"{step.capability:<28}"
            f" {step.decision:<17}"
            f" hash={step.record_hash[:12]}.."
        )

    banner("CHAIN INTEGRITY")
    print(f"verify_all: {g.verify_all()}")

    banner("TAMPER TEST")
    victim = list(g)[0]
    original = victim.reason
    victim.reason = "rewritten history"
    print(f"after edit : {g.verify_all()}")
    victim.reason = original
    print(f"restored   : {g.verify_all()}")


if __name__ == "__main__":
    main()
