"""
Profile Versioning Demo.

Run:

    python -m examples.profile_versioning_demo
"""

from agent_dna import (
    BehaviorDynamics,
    CapabilityManifold,
    FingerprintBuilder,
    ProfileStore,
    SimilarityEngine,
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


def main():

    store = ProfileStore()

    trusted = build_fp([synthetic_normal_trace(seed=i, loops=6) for i in range(8)])

    candidate = build_fp([synthetic_compromised_trace()])

    store.save(trusted, "v1")
    store.save(candidate, "v2")

    print("\nSaved Versions")
    print("=" * 60)

    print(store.versions("sales-agent-01"))

    fp1 = store.load("sales-agent-01", "v1")
    fp2 = store.load("sales-agent-01", "v2")

    report = SimilarityEngine().compare(fp1, fp2)

    print("\nBehavior Evolution")
    print("=" * 60)

    for k, v in report.to_dict().items():
        print(f"{k:24}: {v}")


if __name__ == "__main__":
    main()
