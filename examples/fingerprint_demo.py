"""
Behavioral Fingerprint demo.

Run:

    python -m examples.fingerprint_demo
"""

from agent_dna import (
    BehaviorDynamics,
    CapabilityManifold,
    FingerprintBuilder,
)
from agent_dna.adapters import synthetic_normal_trace


def main():

    training = [synthetic_normal_trace(seed=i, loops=6) for i in range(8)]

    manifold = CapabilityManifold().fit(training)
    dynamics = BehaviorDynamics().fit(training)

    fingerprint = FingerprintBuilder().build(
        agent_id="sales-agent-01",
        manifold=manifold,
        dynamics=dynamics,
    )

    print("\nBehavioral Fingerprint")
    print("=" * 60)

    for k, v in fingerprint.to_dict().items():
        print(f"{k:22}: {v}")


if __name__ == "__main__":
    main()
