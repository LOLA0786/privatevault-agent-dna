"""
End-to-end demo.

1. Learn a trusted profile from several SYNTHETIC normal runs.
2. Score a fresh normal run  -> expect low drift.
3. Score a compromised run   -> expect the drifted actions to light up with
   readable reasons, and show the DeterministicGate escalating (never bypassing).

Run:  python -m examples.demo
"""

from agent_dna import (
    BehaviorDynamics,
    CapabilityManifold,
    DeterministicGate,
    DriftScorer,
    PolicyDecision,
)
from agent_dna.adapters import (
    synthetic_compromised_trace,
    synthetic_normal_trace,
)


def banner(text: str) -> None:
    print("\n" + "=" * 70)
    print(text)
    print("=" * 70)


def main() -> None:

    # ------------------------------------------------------------------
    # Learn trusted profile
    # ------------------------------------------------------------------

    training = [synthetic_normal_trace(seed=i, loops=6) for i in range(8)]

    manifold = CapabilityManifold().fit(training)
    dynamics = BehaviorDynamics().fit(training)

    scorer = DriftScorer(
        manifold,
        dynamics,
    )

    gate = DeterministicGate()

    banner("LEARNED TRUSTED PROFILE")
    print(manifold.summary())

    # ------------------------------------------------------------------
    # Score a fresh normal run
    # ------------------------------------------------------------------

    banner("SCORING A NORMAL RUN (expect low drift)")

    normal = synthetic_normal_trace(
        seed=999,
        loops=2,
    )

    prev = None

    for action in normal.actions:
        signal = scorer.score(
            action,
            prev,
        )

        print(
            f"  {action.capability:<24}"
            f" drift={signal.drift_score:.2f}"
            f" [{signal.severity.value}]"
        )

        prev = action.capability

    # ------------------------------------------------------------------
    # Score compromised run
    # ------------------------------------------------------------------

    banner("SCORING A COMPROMISED RUN (expect drift + escalation)")

    compromised = synthetic_compromised_trace()

    prev = None

    for action in compromised.actions:
        signal = scorer.score(
            action,
            prev,
        )

        decision = gate.decide(
            PolicyDecision.ALLOW,
            signal,
        )

        flag = ">>" if signal.severity.value != "info" else "  "

        print(
            f"{flag} "
            f"{action.capability:<24}"
            f" drift={signal.drift_score:.2f}"
            f" [{signal.severity.value}]"
            f" -> gate={decision.decision.value}"
        )

        if signal.severity.value != "info":
            for reason in signal.reasons:
                print(f"       - {reason}")

        prev = action.capability

    # ------------------------------------------------------------------
    # Boundary check
    # ------------------------------------------------------------------

    banner("BOUNDARY CHECK")

    print(
        "Advisory can escalate ALLOW -> require_approval, but a policy DENY stays DENY."
    )

    signal = scorer.score(
        compromised.actions[-1],
        "storage.bulk_export",
    )

    denied = gate.decide(
        PolicyDecision.DENY,
        signal,
    )

    print(f"  policy=DENY + critical advisory -> {denied.decision.value}")

    print(f"  {denied.rationale}")


if __name__ == "__main__":
    main()
