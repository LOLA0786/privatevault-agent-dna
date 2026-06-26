"""
Streaming Runtime Demo.

Run:

    python -m examples.runtime_demo
"""

from agent_dna import (
    BehaviorDynamics,
    CapabilityManifold,
    DriftScorer,
    RuntimeMonitor,
)

from agent_dna.adapters import (
    synthetic_compromised_trace,
    synthetic_normal_trace,
)


def train():

    training = [
        synthetic_normal_trace(seed=i, loops=6)
        for i in range(8)
    ]

    manifold = CapabilityManifold().fit(training)
    dynamics = BehaviorDynamics().fit(training)

    return DriftScorer(
        manifold,
        dynamics,
    )


def banner(title):
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)


def main():

    scorer = train()
    monitor = RuntimeMonitor(scorer)

    banner("LIVE STREAM")

    trace = synthetic_compromised_trace()

    for action in trace.actions:

        signal = monitor.process(action)

        print(
            f"{action.capability:<28}"
            f" drift={signal.drift_score:.2f}"
            f" severity={signal.severity.value}"
        )

    banner("SESSION SUMMARY")

    print(f"Events Processed : {monitor.event_count}")
    print(f"Critical Events : {len(monitor.critical_events())}")

    if monitor.latest:
        print(f"Last Capability : {monitor.latest.action.capability}")

    print("\nCritical Findings")

    for event in monitor.critical_events():

        print(
            f"\n{event.action.capability}"
        )

        for reason in event.advisory.reasons:
            print(f"  - {reason}")


if __name__ == "__main__":
    main()
