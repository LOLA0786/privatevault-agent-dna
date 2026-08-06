"""
Streaming Runtime Demo.

Run:

    python -m examples.runtime_demo
"""

from agent_dna import (
    BehaviorDynamics,
    CapabilityManifold,
    DriftScorer,
    InvariantEngine,
    InvariantLearner,
    RuntimeMonitor,
)
from agent_dna.adapters import (
    synthetic_compromised_trace,
    synthetic_normal_trace,
)
from agent_dna.observability.logger import get_logger

logger = get_logger("pv_demo")


def train():
    training = [synthetic_normal_trace(seed=i, loops=6) for i in range(8)]
    manifold = CapabilityManifold().fit(training)
    dynamics = BehaviorDynamics().fit(training)
    learner = InvariantLearner()
    invariants = learner.fit(training)
    engine = InvariantEngine(invariants)
    return DriftScorer(manifold, dynamics, engine)


def banner(title):
    logger.info("session_banner", extra={"title": title})


def main():
    scorer = train()
    from agent_dna.decision import DecisionEngine

    engine = DecisionEngine(scorer=scorer)
    monitor = RuntimeMonitor(engine)
    banner("LIVE STREAM")
    trace = synthetic_compromised_trace()
    for action in trace.actions:
        signal = monitor.process(action)
        logger.info(
            "runtime_event",
            extra={
                "capability": action.capability,
                "drift_score": signal.drift_score,
                "severity": signal.severity.value,
                "agent_id": action.agent_id,
            },
        )
    banner("SESSION SUMMARY")
    logger.info(
        "session_summary",
        extra={
            "event_count": monitor.event_count,
            "critical_events": len(monitor.critical_events()),
        },
    )
    if monitor.latest:
        logger.info(
            "summary_latest",
            extra={
                "last_capability": monitor.latest.action.capability,
            },
        )
    logger.info("critical_findings_header")
    for event in monitor.critical_events():
        logger.info(
            "critical_event",
            extra={
                "capability": event.action.capability,
                "reasons": event.advisory.reasons,
            },
        )


if __name__ == "__main__":
    main()
