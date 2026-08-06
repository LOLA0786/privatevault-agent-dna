"""
Behavioral Profile Diff Demo.

Run:

    python -m examples.diff_demo
"""

from agent_dna import (
    BehaviorDynamics,
    CapabilityManifold,
    FingerprintBuilder,
    ProfileDiffEngine,
)
from agent_dna.adapters import (
    synthetic_compromised_trace,
    synthetic_normal_trace,
)


def build_fp(traces):
    manifold = CapabilityManifold().fit(traces)
    dynamics = BehaviorDynamics().fit(traces)

    return FingerprintBuilder().build(
        agent_id="sales-agent-01",
        manifold=manifold,
        dynamics=dynamics,
    )


def section(title):
    print("\n" + "=" * 68)
    print(title)
    print("=" * 68)


def main():

    trusted = build_fp([synthetic_normal_trace(seed=i, loops=6) for i in range(8)])

    candidate = build_fp([synthetic_compromised_trace()])

    report = ProfileDiffEngine().diff(
        trusted,
        candidate,
    )

    section("PrivateVault Agent DNA™")
    print("Behavioral Identity Report")

    print("\nOverall Similarity")
    print(f"  {report.overall_similarity:.2%}")

    print("\nRisk")
    print(f"  {report.risk}")

    print("\nAdded Capabilities")
    if report.added_capabilities:
        for item in report.added_capabilities:
            print(f"  + {item}")
    else:
        print("  None")

    print("\nRemoved Capabilities")
    if report.removed_capabilities:
        for item in report.removed_capabilities:
            print(f"  - {item}")
    else:
        print("  None")

    print("\nNew Behavior Transitions")
    if report.added_transitions:
        for item in report.added_transitions:
            print(f"  + {item}")
    else:
        print("  None")

    print("\nRemoved Transitions")
    if report.removed_transitions:
        for item in report.removed_transitions:
            print(f"  - {item}")
    else:
        print("  None")

    print("\nAssessment")
    print(f"  {report.summary}")


if __name__ == "__main__":
    main()
