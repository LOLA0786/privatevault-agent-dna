from agent_dna import (
    AuthorizationPolicy,
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


trusted = build_fp([synthetic_normal_trace(seed=i, loops=6) for i in range(8)])

candidate = build_fp([synthetic_compromised_trace()])

policy = AuthorizationPolicy()

policy.grant(
    agent_id="sales-agent-01",
    capability="payments.initiate_wire",
    approved_by="Operations",
    ticket="CHG-20481",
)

report = ProfileDiffEngine().diff(
    trusted,
    candidate,
    policy,
)

print("\nPrivateVault Agent DNA™")
print("=" * 70)

print(f"\nOverall Similarity : {report.overall_similarity:.2%}")
print(f"Risk               : {report.risk}")

print("\nAuthorized Evolution")
print("--------------------")

if report.authorized_additions:
    policy = AuthorizationPolicy()

    for capability in report.authorized_additions:
        grant = policy.lookup(
            trusted.agent_id,
            capability,
        )

        if grant:
            print(f"✓ {grant.capability}  ({grant.approved_by}, {grant.ticket})")
        else:
            print(f"✓ {capability}")

else:
    print("None")

print("\nUnexpected Evolution")
print("--------------------")

if report.unauthorized_additions:
    for cap in report.unauthorized_additions:
        print(f"⚠ {cap}")
else:
    print("None")

print("\nSummary")
print("-------")
print(report.summary)
