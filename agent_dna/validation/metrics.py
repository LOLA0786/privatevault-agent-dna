"""Model-validation metrics for the advisory drift scorer.

Design constraints (mirroring the enforcement core's discipline):

- Standard library only. Every number here must be recomputable by
  ``tools/verify_validation.py`` without installing this package.
- Deterministic: no sampling, no RNG, no floating-point ordering
  hazards beyond IEEE-754 summation (kept stable via math.fsum).
- Honest: metrics that require calibrated probabilities (Brier,
  log loss, ECE) are refused for scores declared as *ranking* scores.
  Refusal happens in report.py; this module simply computes.
- Safeguarded: any segment below the minimum sample count, or with a
  single class, yields status != "ok" and metric None -- never a
  misleading number.

Formulas and limitations are documented in docs/VALIDATION-MATH.md.
"""

from __future__ import annotations

import math
from bisect import bisect_left, bisect_right
from collections import defaultdict
from dataclasses import dataclass

# ---------------------------------------------------------------- safeguards

DEFAULT_MIN_SAMPLES = 30
Z_95 = 1.959963984540054  # two-sided 95%


def wilson_interval(successes: int, n: int, z: float = Z_95) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    Preferred over the normal approximation because it behaves at the
    boundaries (p near 0 or 1) and for small n -- exactly the regimes
    small per-segment samples put us in.
    """
    if n <= 0:
        raise ValueError("wilson_interval requires n > 0")
    if not 0 <= successes <= n:
        raise ValueError("successes must be in [0, n]")
    p = successes / n
    z2 = z * z
    denom = 1 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    half = (z / denom) * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
    return (max(0.0, center - half), min(1.0, center + half))


# ---------------------------------------------------------------- AUC


def _pair_wins_ties(pos_scores: list[float], sorted_neg: list[float]) -> tuple[float, int]:
    """Sum over all (pos, neg) pairs of [1 if pos>neg, 0.5 if tie].

    sorted_neg must be pre-sorted ascending. O(len(pos) * log len(neg)).
    Returns (weighted_wins, n_pairs).
    """
    total = 0.0
    for s in pos_scores:
        lo = bisect_left(sorted_neg, s)
        hi = bisect_right(sorted_neg, s)
        total += lo + 0.5 * (hi - lo)
    return total, len(pos_scores) * len(sorted_neg)


def auc(scores: list[float], labels: list[int]) -> float | None:
    """Mann-Whitney AUC with tie correction: P(S+ > S-) + 0.5 P(tie).

    Returns None if either class is absent (single-class safeguard).
    """
    if len(scores) != len(labels):
        raise ValueError("scores and labels length mismatch")
    pos = [s for s, y in zip(scores, labels, strict=True) if y == 1]
    neg = sorted(s for s, y in zip(scores, labels, strict=True) if y == 0)
    if not pos or not neg:
        return None
    wins, pairs = _pair_wins_ties(pos, neg)
    return wins / pairs


@dataclass(frozen=True)
class AUCDecomposition:
    """Exact decomposition of global pairwise AUC into within-segment
    and between-segment pair contributions.

    Identity (checked by the independent verifier):
        auc_global == within_contribution + between_contribution
    where each contribution is (weighted wins over that pair subset)
    divided by the TOTAL number of (pos, neg) pairs. The share fields
    give the fraction of pairs in each subset.
    """

    auc_global: float
    within_contribution: float
    between_contribution: float
    within_pair_share: float
    between_pair_share: float
    n_pairs: int


def auc_decomposition(
    scores: list[float],
    labels: list[int],
    segments: list[str],
) -> AUCDecomposition | None:
    """Decompose global AUC by segment membership of each (pos, neg) pair.

    A pair is *within* if both members share a segment key, *between*
    otherwise. The two contributions sum exactly to the global AUC --
    an identity, not an approximation -- so a reviewer can see how much
    of the headline ranking quality comes from separating segments
    from each other versus separating outcomes inside a segment.
    """
    if not (len(scores) == len(labels) == len(segments)):
        raise ValueError("scores, labels, segments length mismatch")
    pos_by_seg: dict[str, list[float]] = defaultdict(list)
    neg_by_seg: dict[str, list[float]] = defaultdict(list)
    for s, y, g in zip(scores, labels, segments, strict=True):
        (pos_by_seg if y == 1 else neg_by_seg)[g].append(s)
    n_pos = sum(len(v) for v in pos_by_seg.values())
    n_neg = sum(len(v) for v in neg_by_seg.values())
    if n_pos == 0 or n_neg == 0:
        return None
    n_pairs = n_pos * n_neg

    sorted_neg = {g: sorted(v) for g, v in neg_by_seg.items()}
    within_wins = 0.0
    within_pairs = 0
    total_wins = 0.0
    for gp, plist in pos_by_seg.items():
        for gn, nlist in sorted_neg.items():
            wins, pairs = _pair_wins_ties(plist, nlist)
            total_wins += wins
            if gp == gn:
                within_wins += wins
                within_pairs += pairs

    between_wins = total_wins - within_wins
    between_pairs = n_pairs - within_pairs
    return AUCDecomposition(
        auc_global=total_wins / n_pairs,
        within_contribution=within_wins / n_pairs,
        between_contribution=between_wins / n_pairs,
        within_pair_share=within_pairs / n_pairs,
        between_pair_share=between_pairs / n_pairs,
        n_pairs=n_pairs,
    )


# ------------------------------------------------- calibration (probability scores ONLY)


def brier_score(probs: list[float], labels: list[int]) -> float:
    """Mean squared error of predicted probability vs outcome."""
    _check_probs(probs, labels)
    return math.fsum((p - y) ** 2 for p, y in zip(probs, labels, strict=True)) / len(probs)


def log_loss(probs: list[float], labels: list[int], eps: float = 1e-15) -> float:
    """Negative mean log-likelihood, probabilities clipped to (eps, 1-eps)."""
    _check_probs(probs, labels)
    total = 0.0
    for p, y in zip(probs, labels, strict=True):
        p = min(max(p, eps), 1 - eps)
        total += -(y * math.log(p) + (1 - y) * math.log(1 - p))
    return total / len(probs)


def expected_calibration_error(
    probs: list[float], labels: list[int], n_bins: int = 10
) -> float:
    """ECE with equal-width bins: sum_b (n_b/N) * |acc_b - conf_b|.

    Known limitation (documented): binning choice affects the value;
    we fix equal-width deciles and record n_bins in the report so the
    number is reproducible, not tunable after the fact.
    """
    _check_probs(probs, labels)
    if n_bins < 2:
        raise ValueError("n_bins must be >= 2")
    n = len(probs)
    sums = [0.0] * n_bins
    hits = [0] * n_bins
    counts = [0] * n_bins
    for p, y in zip(probs, labels, strict=True):
        b = min(int(p * n_bins), n_bins - 1)
        counts[b] += 1
        sums[b] += p
        hits[b] += y
    ece = 0.0
    for b in range(n_bins):
        if counts[b] == 0:
            continue
        acc = hits[b] / counts[b]
        conf = sums[b] / counts[b]
        ece += (counts[b] / n) * abs(acc - conf)
    return ece


def _check_probs(probs: list[float], labels: list[int]) -> None:
    if len(probs) != len(labels):
        raise ValueError("probs and labels length mismatch")
    if not probs:
        raise ValueError("empty inputs")
    for p in probs:
        if not (0.0 <= p <= 1.0) or not math.isfinite(p):
            raise ValueError(f"probability out of [0,1]: {p!r}")
    for y in labels:
        if y not in (0, 1):
            raise ValueError(f"labels must be 0/1, got {y!r}")


# ------------------------------------------------------- segment reliability


@dataclass(frozen=True)
class SegmentReliability:
    key: str
    n: int
    n_pos: int
    prevalence: float | None
    prevalence_ci: tuple[float, float] | None
    auc: float | None
    status: str  # "ok" | "insufficient_samples" | "single_class"


def segment_reliability(
    scores: list[float],
    labels: list[int],
    segments: list[str],
    min_samples: int = DEFAULT_MIN_SAMPLES,
) -> list[SegmentReliability]:
    """Per-segment prevalence (with Wilson CI) and AUC, safeguarded.

    A segment below min_samples reports status "insufficient_samples"
    and no point estimates at all -- a small-n number in a report is a
    number someone will quote.
    """
    by_seg: dict[str, list[tuple[float, int]]] = defaultdict(list)
    for s, y, g in zip(scores, labels, segments, strict=True):
        by_seg[g].append((s, y))
    out: list[SegmentReliability] = []
    for key in sorted(by_seg):
        rows = by_seg[key]
        n = len(rows)
        n_pos = sum(y for _, y in rows)
        if n < min_samples:
            out.append(SegmentReliability(key, n, n_pos, None, None, None,
                                          "insufficient_samples"))
            continue
        if n_pos == 0 or n_pos == n:
            out.append(SegmentReliability(
                key, n, n_pos, n_pos / n, wilson_interval(n_pos, n), None,
                "single_class"))
            continue
        seg_auc = auc([s for s, _ in rows], [y for _, y in rows])
        out.append(SegmentReliability(
            key, n, n_pos, n_pos / n, wilson_interval(n_pos, n), seg_auc, "ok"))
    return out


def cross_segments(agents: list[str], capabilities: list[str]) -> list[str]:
    """agent × capability segment keys, e.g. 'treasury-07|payments.transfer'."""
    if len(agents) != len(capabilities):
        raise ValueError("agents and capabilities length mismatch")
    return [f"{a}|{c}" for a, c in zip(agents, capabilities, strict=True)]
