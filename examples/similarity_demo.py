"""
Behavioral Identity Similarity Demo.

Run:

    python -m examples.similarity_demo
"""

from agent_dna import (
    BehaviorDynamics,
    CapabilityManifold,
    FingerprintBuilder,
    SimilarityEngine,
)
from agent_dna.adapters import (
    synthetic_compromised_trace,
    synthetic_normal_trace,
)


def build_fp(traces, agent_id="sales-agent-01"):
    manifold = CapabilityManifold().fit(traces)
    dynamics = BehaviorDynamics().fit(traces)

    return FingerprintBuilder().build(
        agent_id=agent_id,
        manifold=manifold,
        dynamics=dynamics,
    )


def main():

    # Trusted profile
    trusted_training = [synthetic_normal_trace(seed=i, loops=6) for i in range(8)]

    trusted = build_fp(trusted_training)

    # New version behaving normally
    candidate_normal = build_fp([synthetic_normal_trace(seed=999, loops=6)])

    # Compromised behavior
    candidate_attack = build_fp([synthetic_compromised_trace()])

    engine = SimilarityEngine()

    print("\n==============================")
    print("Trusted vs Normal")
    print("==============================")
    print(
        engine.compare(
            trusted,
            candidate_normal,
        ).to_dict()
    )

    print("\n==============================")
    print("Trusted vs Compromised")
    print("==============================")
    print(
        engine.compare(
            trusted,
            candidate_attack,
        ).to_dict()
    )


if __name__ == "__main__":
    main()
