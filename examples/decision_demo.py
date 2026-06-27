"""
Unified runtime demo — the single coherent story.

Agent DNA learns identity, validates behavioural contracts, checks approved
evolution, and emits ONE enforcement decision per action. Instead of four
independent outputs, every event resolves to ALLOW / REQUIRE_APPROVAL / BLOCK
with the reason that drove it.

Run:  python -m examples.decision_demo
"""

from agent_dna import (
    BehaviorDynamics,
    CapabilityGrant,
    CapabilityManifold,
    DecisionEngine,
    DriftScorer,
    GrantAuthorizationPolicy,
    SequenceInvariantEngine,
)
from agent_dna.adapters import synthetic_compromised_trace, synthetic_normal_trace


def main() -> None:
    # 1. learn the trusted profile from normal runs
    training = [synthetic_normal_trace(seed=i, loops=6) for i in range(8)]
    manifold = CapabilityManifold().fit(training)
    dynamics = BehaviorDynamics().fit(training)
    scorer = DriftScorer(manifold, dynamics)
    baseline_caps = list(manifold.capability_counts.keys())

    # 2. policy collaborators (swap your real ones in here)
    invariants = SequenceInvariantEngine(forbidden_transitions=[
        # segregation-of-duties contracts, authored from policy
        ("crm.read_contact", "payments.initiate_wire"),
        ("email.send", "payments.initiate_wire"),
    ])
    # storage.bulk_export was approved via a change ticket; wire was NOT.
    authz = GrantAuthorizationPolicy(
        baseline_capabilities=baseline_caps,
        grants=[CapabilityGrant("storage.bulk_export", approved_by="Security Team",
                                ticket="OPS-842")],
    )

    # 3. one orchestrator owns the verdict
    engine = DecisionEngine(scorer=scorer, invariants=invariants, authorizer=authz)

    print("=" * 68)
    print("UNIFIED RUNTIME DECISION  (learned drift + invariants + authorization)")
    print("=" * 68)
    trace = synthetic_compromised_trace()
    prev = None
    for action in trace.actions:
        d = engine.decide(action, prev)
        print(f"  {action.capability:<24} {d.decision.value:<16} via {d.triggered_by}")
        if d.decision.value != "allow":
            print(f"       {d.reason}")
        prev = action.capability

    print("\n" + "=" * 68)
    print("PRECEDENCE CHECK")
    print("=" * 68)
    print("payments.initiate_wire is BOTH unauthorised AND high-drift, but the")
    print("invariant (money-movement may not follow an outbound email) wins -> BLOCK.")
    print("storage.bulk_export is authorised by ticket OPS-842, yet its runtime")
    print("behaviour is anomalous -> REQUIRE_APPROVAL (grant explains novelty, drift")
    print("still escalates). One capability, one coherent verdict.")


if __name__ == "__main__":
    main()
