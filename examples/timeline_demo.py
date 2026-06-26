"""
Behavior Timeline Demo.

Run:

    python -m examples.timeline_demo
"""

from agent_dna import (
    BehaviorTimeline,
    BehaviorDynamics,
    CapabilityManifold,
    FingerprintBuilder,
)

from agent_dna.adapters import (
    synthetic_normal_trace,
    synthetic_compromised_trace,
)


def build_fp(traces):
    manifold = CapabilityManifold().fit(traces)
    dynamics = BehaviorDynamics().fit(traces)

    return FingerprintBuilder().build(
        agent_id="sales-agent-01",
        manifold=manifold,
        dynamics=dynamics,
    )


def main():

    timeline = BehaviorTimeline()

    # Baseline
    timeline.add(
        "v1",
        build_fp([
            synthetic_normal_trace(seed=i, loops=6)
            for i in range(8)
        ]),
    )

    # Small evolution
    timeline.add(
        "v2",
        build_fp([
            synthetic_normal_trace(seed=999, loops=6)
        ]),
    )

    # Large drift
    timeline.add(
        "v3",
        build_fp([
            synthetic_compromised_trace()
        ]),
    )

    print("\nPrivateVault Agent DNA Timeline")
    print("=" * 65)

    print("Versions")
    print("--------")
    print(" -> ".join(timeline.versions()))

    print("\nEvolution")
    print("---------")

    for i, result in enumerate(
        timeline.compare_adjacent(),
        start=1,
    ):
        print(
            f"v{i} -> v{i+1}"
            f"  similarity={result.overall_similarity:.2%}"
            f"  risk={result.risk}"
        )

    print("\nBehavior Stability")
    print("------------------")
    print(f"{timeline.stability_score()}%")

    print("\nLatest Profile")
    print("--------------")
    print(timeline.latest().behavior_hash[:16] + "...")


if __name__ == "__main__":
    main()
