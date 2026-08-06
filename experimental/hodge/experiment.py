"""A/B: Hodge harmonic energy vs the current four-method weighted score.

Deliberately includes a family where the topological method should NOT help
(sequential escalation is a path, not a cycle). A method evaluated only on
cases it was designed for tells you nothing.
"""

from __future__ import annotations

import numpy as np

from hodge import ComplexBuilder, decompose, verify_chain_complex

AGENTS = [
    "treasury",
    "ops_a",
    "ops_b",
    "approver_a",
    "approver_b",
    "vendor_api",
    "ledger",
    "recon",
]


def _jitter(rng: np.random.Generator, base: float) -> float:
    return float(base * rng.uniform(0.75, 1.35))


def benign_hierarchy(rng: np.random.Generator) -> ComplexBuilder:
    """Ordinary delegation. Treasury down to vendor, dual-control co-signed."""
    b = ComplexBuilder()
    b.add_flow("treasury", "ops_a", _jitter(rng, 100))
    b.add_flow("treasury", "ops_b", _jitter(rng, 80))
    b.add_flow("ops_a", "vendor_api", _jitter(rng, 60))
    b.add_flow("ops_b", "vendor_api", _jitter(rng, 50))
    b.add_flow("ops_a", "ledger", _jitter(rng, 30))
    b.add_flow("ops_b", "recon", _jitter(rng, 20))
    b.add_cosignature("treasury", "ops_a", "approver_a")
    b.add_cosignature("treasury", "ops_b", "approver_b")
    return b


def benign_cosigned_loop(rng: np.random.Generator) -> ComplexBuilder:
    """Circular flow that WAS jointly approved.

    A cycle detector fires here. It should not be an alarm: every hop sits
    inside a co-signed face. This family is the false-positive test.
    """
    b = ComplexBuilder()
    b.add_flow("treasury", "ops_a", _jitter(rng, 90))
    b.add_flow("ops_a", "approver_a", _jitter(rng, 85))
    b.add_flow("approver_a", "treasury", _jitter(rng, 80))
    b.add_cosignature("treasury", "ops_a", "approver_a")
    b.add_flow("ops_b", "vendor_api", _jitter(rng, 40))
    b.add_flow("treasury", "ops_b", _jitter(rng, 45))
    b.add_cosignature("treasury", "ops_b", "approver_b")
    return b


def attack_authority_cycle(rng: np.random.Generator) -> ComplexBuilder:
    """A approves B, but B's authority derives from A. No joint sign-off."""
    b = ComplexBuilder()
    b.add_flow("treasury", "ops_a", _jitter(rng, 70))
    b.add_flow("ops_a", "approver_a", _jitter(rng, 95))
    b.add_flow("approver_a", "ops_b", _jitter(rng, 90))
    b.add_flow("ops_b", "ops_a", _jitter(rng, 88))
    b.add_cosignature("treasury", "ops_b", "approver_b")
    b.add_flow("ops_b", "vendor_api", _jitter(rng, 35))
    return b


def attack_consensus_evasion(rng: np.random.Generator) -> ComplexBuilder:
    """Authority circulates on a path routing around the co-signed region."""
    b = ComplexBuilder()
    b.add_flow("treasury", "ops_a", _jitter(rng, 60))
    b.add_flow("ops_a", "vendor_api", _jitter(rng, 92))
    b.add_flow("vendor_api", "ledger", _jitter(rng, 90))
    b.add_flow("ledger", "recon", _jitter(rng, 88))
    b.add_flow("recon", "ops_a", _jitter(rng, 86))
    b.add_cosignature("treasury", "ops_b", "approver_b")
    b.add_flow("treasury", "ops_b", _jitter(rng, 25))
    return b


def attack_sequential_escalation(rng: np.random.Generator) -> ComplexBuilder:
    """Raise limit, add beneficiary, transfer. A PATH, not a cycle.

    Hodge should add nothing here. Included to test the method's limits.
    """
    b = ComplexBuilder()
    b.add_flow("ops_a", "treasury", _jitter(rng, 95))
    b.add_flow("treasury", "ledger", _jitter(rng, 90))
    b.add_flow("ledger", "vendor_api", _jitter(rng, 120))
    b.add_flow("treasury", "ops_b", _jitter(rng, 30))
    b.add_cosignature("treasury", "ops_b", "approver_b")
    return b


FAMILIES = {
    "benign_hierarchy": (benign_hierarchy, 0),
    "benign_cosigned_loop": (benign_cosigned_loop, 0),
    "attack_authority_cycle": (attack_authority_cycle, 1),
    "attack_consensus_evasion": (attack_consensus_evasion, 1),
    "attack_sequential_escalation": (attack_sequential_escalation, 1),
}


def _has_directed_cycle(builder: ComplexBuilder) -> float:
    complex_, _ = builder.build()
    return 1.0 if complex_.n_edges >= complex_.n_agents else 0.0


def baseline_score(builder: ComplexBuilder) -> float:
    """Four signals, equal weights, manual threshold. RECONSTRUCTED, not the
    real pipeline - do not quote this comparison."""
    complex_, flow = builder.build()

    cycle = _has_directed_cycle(builder)

    degree = np.zeros(complex_.n_agents)
    for i, j in complex_.edges:
        degree[i] += 1
        degree[j] += 1
    spread = degree.std()
    degree_signal = min(1.0, float(spread / (degree.mean() + 1e-9)))

    net = np.zeros(complex_.n_agents)
    for index, (i, j) in enumerate(complex_.edges):
        net[i] -= flow[index]
        net[j] += flow[index]
    imbalance = min(1.0, float(np.abs(net).max() / (np.abs(flow).sum() + 1e-9)))

    magnitude = np.abs(flow)
    novelty = min(
        1.0,
        float((magnitude > magnitude.mean()).sum() / max(1, len(magnitude))),
    )

    return float(np.mean([cycle, degree_signal, imbalance, novelty]))


def hodge_score(builder: ComplexBuilder) -> float:
    """Harmonic energy: circulation not attributable to any co-signed face."""
    complex_, flow = builder.build()
    return decompose(complex_, flow).harmonic_energy


def wilson(successes: int, trials: int, z: float = 1.96) -> tuple[float, float]:
    if trials == 0:
        return (0.0, 0.0)
    p = successes / trials
    denom = 1 + z**2 / trials
    centre = (p + z**2 / (2 * trials)) / denom
    margin = (z * np.sqrt(p * (1 - p) / trials + z**2 / (4 * trials**2))) / denom
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def auc(scores: list[float], labels: list[int]) -> float:
    pos = [s for s, y in zip(scores, labels, strict=True) if y == 1]
    neg = [s for s, y in zip(scores, labels, strict=True) if y == 0]
    if not pos or not neg:
        return float("nan")
    wins = sum((p > n) + 0.5 * (p == n) for p in pos for n in neg)
    return float(wins / (len(pos) * len(neg)))


def main(n_per_family: int = 200, seed: int = 20260731) -> None:
    rng = np.random.default_rng(seed)

    rows: list[tuple[str, int, float, float]] = []
    energies: dict[str, list[tuple[float, float, float]]] = {}

    for name, (generator, label) in FAMILIES.items():
        energies[name] = []
        for _ in range(n_per_family):
            builder = generator(rng)
            complex_, flow = builder.build()

            identity = verify_chain_complex(complex_)
            if identity > 1e-9:
                raise AssertionError(
                    f"chain complex broken in {name}: ||B1@B2|| = {identity}"
                )

            components = decompose(complex_, flow)
            if components.residual() > 1e-9:
                raise AssertionError(f"decomposition residual in {name}")

            energies[name].append(
                (
                    components.gradient_energy,
                    components.curl_energy,
                    components.harmonic_energy,
                )
            )
            rows.append((name, label, baseline_score(builder), hodge_score(builder)))

    print("=" * 74)
    print("ENERGY DECOMPOSITION BY FAMILY (mean fraction of total flow energy)")
    print("=" * 74)
    print(f"{'family':<32}{'gradient':>11}{'curl':>11}{'harmonic':>11}")
    for name, values in energies.items():
        arr = np.array(values)
        print(
            f"{name:<32}{arr[:, 0].mean():>11.3f}"
            f"{arr[:, 1].mean():>11.3f}{arr[:, 2].mean():>11.3f}"
        )

    labels = [r[1] for r in rows]
    base = [r[2] for r in rows]
    hodge = [r[3] for r in rows]

    print()
    print("=" * 74)
    print("SEPARATION (all families pooled)")
    print("=" * 74)
    print(f"baseline four-method AUC : {auc(base, labels):.3f}")
    print(f"hodge harmonic AUC       : {auc(hodge, labels):.3f}")

    print()
    print("=" * 74)
    print("THE DISCRIMINATION THAT MATTERS")
    print("co-signed circulation (benign) vs uncosigned circulation (attack)")
    print("=" * 74)
    subset = [
        r for r in rows if r[0] in ("benign_cosigned_loop", "attack_authority_cycle")
    ]
    sub_labels = [r[1] for r in subset]
    print(f"baseline four-method AUC : {auc([r[2] for r in subset], sub_labels):.3f}")
    print(f"hodge harmonic AUC       : {auc([r[3] for r in subset], sub_labels):.3f}")

    print()
    print("=" * 74)
    print("HONEST NEGATIVE: sequential escalation is a path, not a cycle")
    print("=" * 74)
    subset = [
        r for r in rows if r[0] in ("benign_hierarchy", "attack_sequential_escalation")
    ]
    sub_labels = [r[1] for r in subset]
    print(f"baseline four-method AUC : {auc([r[2] for r in subset], sub_labels):.3f}")
    print(f"hodge harmonic AUC       : {auc([r[3] for r in subset], sub_labels):.3f}")

    print()
    print("=" * 74)
    print("OPERATING POINT (harmonic energy > 0.05, no fitting)")
    print("=" * 74)
    for name, (_, label) in FAMILIES.items():
        fires = [1 for r in rows if r[0] == name and r[3] > 0.05]
        trials = n_per_family
        lo, hi = wilson(len(fires), trials)
        kind = "detect" if label == 1 else "FALSE POS"
        print(
            f"{name:<32}{kind:>11}  {len(fires) / trials:>6.1%}  [{lo:.1%}, {hi:.1%}]"
        )


if __name__ == "__main__":
    main()
