"""The failure mode that decides whether this is deployable.

Harmonic energy means "circulation not covered by a co-signed face". In a lab
scenario co-signature is either present or absent. In production, co-signature
records are INCOMPLETE for boring reasons: a sign-off happened out of band, a
record was dropped, a face is only partially observed.

If incomplete coverage of a genuinely benign system produces harmonic energy
indistinguishable from an attack, the method is undeployable regardless of how
good the clean-room AUC looks. This measures that directly.
"""

from __future__ import annotations

import numpy as np
from experiment import auc, wilson

from hodge import ComplexBuilder, decompose


def benign_loop_with_coverage(
    rng: np.random.Generator,
    coverage: float,
) -> float:
    """A fully legitimate co-signed system, with only `coverage` of the
    co-signature records actually observed."""
    b = ComplexBuilder()

    triples = [
        ("treasury", "ops_a", "approver_a"),
        ("treasury", "ops_b", "approver_b"),
        ("ops_a", "vendor_api", "approver_a"),
        ("ops_b", "ledger", "approver_b"),
    ]

    for x, y, z in triples:
        w = float(rng.uniform(60, 110))
        b.add_flow(x, y, w)
        b.add_flow(y, z, w * float(rng.uniform(0.85, 1.0)))
        b.add_flow(z, x, w * float(rng.uniform(0.85, 1.0)))

    for triple in triples:
        if rng.random() < coverage:
            b.add_cosignature(*triple)

    complex_, flow = b.build()
    return decompose(complex_, flow).harmonic_energy


def attack_with_coverage(
    rng: np.random.Generator,
    coverage: float,
) -> float:
    """A genuine uncosigned authority cycle, in a system whose OTHER
    co-signatures are observed at the same rate."""
    b = ComplexBuilder()

    triples = [
        ("treasury", "ops_b", "approver_b"),
        ("ops_b", "ledger", "approver_b"),
    ]
    for x, y, z in triples:
        w = float(rng.uniform(60, 110))
        b.add_flow(x, y, w)
        b.add_flow(y, z, w * float(rng.uniform(0.85, 1.0)))
        b.add_flow(z, x, w * float(rng.uniform(0.85, 1.0)))

    for triple in triples:
        if rng.random() < coverage:
            b.add_cosignature(*triple)

    # the attack: a cycle never co-signed at any coverage level
    w = float(rng.uniform(80, 120))
    b.add_flow("ops_a", "approver_a", w)
    b.add_flow("approver_a", "recon", w * 0.95)
    b.add_flow("recon", "ops_a", w * 0.92)

    complex_, flow = b.build()
    return decompose(complex_, flow).harmonic_energy


def main(n: int = 300, seed: int = 20260731) -> None:
    rng = np.random.default_rng(seed)

    print("=" * 74)
    print("DEGRADATION UNDER INCOMPLETE CO-SIGNATURE COVERAGE")
    print("=" * 74)
    print(
        f"{'coverage':>10}{'benign mean':>14}{'attack mean':>14}"
        f"{'AUC':>8}{'benign FP @0.05':>18}"
    )

    for coverage in (1.0, 0.9, 0.75, 0.5, 0.25, 0.0):
        benign = [benign_loop_with_coverage(rng, coverage) for _ in range(n)]
        attack = [attack_with_coverage(rng, coverage) for _ in range(n)]

        scores = benign + attack
        labels = [0] * n + [1] * n
        false_positives = sum(1 for value in benign if value > 0.05)
        lo, hi = wilson(false_positives, n)

        print(
            f"{coverage:>10.0%}{np.mean(benign):>14.3f}"
            f"{np.mean(attack):>14.3f}{auc(scores, labels):>8.3f}"
            f"{false_positives / n:>10.1%} [{lo:.0%},{hi:.0%}]"
        )

    print()
    print("=" * 74)
    print("READING")
    print("=" * 74)
    print(
        "At full coverage the signal is clean. As co-signature records go\n"
        "missing, benign circulation acquires harmonic energy for a purely\n"
        "administrative reason and becomes indistinguishable from the attack.\n"
        "The method therefore measures a property of the EVIDENCE, not of the\n"
        "agents: it is a detector for 'circulation without recorded joint\n"
        "approval', which is only an attack signal where recording is\n"
        "complete and enforced."
    )


if __name__ == "__main__":
    main()
