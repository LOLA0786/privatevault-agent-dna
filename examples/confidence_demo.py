"""
Behavior Profile Confidence Demo.
"""

from agent_dna import (
    CapabilityManifold,
    ConfidenceEstimator,
)
from agent_dna.adapters import synthetic_normal_trace

estimator = ConfidenceEstimator()

small = CapabilityManifold().fit([synthetic_normal_trace(seed=1, loops=2)])

medium = CapabilityManifold().fit(
    [synthetic_normal_trace(seed=i, loops=6) for i in range(5)]
)

large = CapabilityManifold().fit(
    [synthetic_normal_trace(seed=i, loops=25) for i in range(20)]
)


for name, manifold in [
    ("Small Profile", small),
    ("Medium Profile", medium),
    ("Large Profile", large),
]:
    c = estimator.estimate(manifold)

    print("\n" + "=" * 65)
    print(name)
    print("=" * 65)

    print(f"Training Actions : {c.training_actions}")
    print(f"Confidence Score : {c.score:.2f}")
    print(f"Confidence Level : {c.level}")
    print(f"Rationale        : {c.rationale}")
