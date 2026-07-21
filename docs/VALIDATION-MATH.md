# pv-validation/1 — Mathematical Documentation

Scope: the ADVISORY drift signal only. Nothing here touches the
deterministic levels L0–L4; the only runtime effect any validation
artifact can have is a **tighten-only** adjustment at the existing
`drift` precedence level (see `agent_dna/validation/guard.py`).
Every formula below is implemented standard-library-only and is
recomputable by `tools/verify_validation.py` without this package.

## 1. Wilson score interval

For k successes in n trials, p̂ = k/n, z the two-sided normal quantile
(z = 1.9600 for 95%):

    center = (p̂ + z²/2n) / (1 + z²/n)
    half   = (z / (1 + z²/n)) · √( p̂(1−p̂)/n + z²/4n² )
    CI     = [center − half, center + half], clipped to [0, 1]

Chosen over the Wald interval because it does not collapse at p̂ ∈
{0, 1} and remains sane at the small per-segment n this system
actually sees. Limitation: it is an interval for a binomial
proportion under i.i.d. sampling; correlated outcomes (e.g. one
incident generating many labelled actions) make it anti-conservative.

## 2. AUC (Mann–Whitney with ties)

With positive scores {sᵢ⁺} (count P) and negative scores {sⱼ⁻}
(count N):

    AUC = (1 / PN) · Σᵢ Σⱼ [ 1(sᵢ⁺ > sⱼ⁻) + ½·1(sᵢ⁺ = sⱼ⁻) ]

Interpretation: probability a uniformly random positive outranks a
uniformly random negative, ties counted half. AUC is a **ranking**
statistic: it is invariant to any strictly monotone transform of the
scores, which is precisely why it says nothing about calibration.

## 3. Exact global-AUC decomposition (within/between segment)

Partition the PN (positive, negative) pairs by the segment keys of
their members: W = pairs with equal keys, B = the rest. Define

    C_within  = (1/PN) · Σ_{(i,j) ∈ W} [1(sᵢ⁺ > sⱼ⁻) + ½·ties]
    C_between = (1/PN) · Σ_{(i,j) ∈ B} [1(sᵢ⁺ > sⱼ⁻) + ½·ties]

Then, **as an identity** (verified to 1e−9 by the independent
verifier, and to 1e−12 in tests):

    AUC = C_within + C_between
    |W|/PN + |B|/PN = 1

Why it matters: a scorer can post a high headline AUC purely by
separating segments from each other (e.g. treasury agents simply
score higher than CRM agents) while being useless *inside* any one
segment — which is where enforcement decisions actually happen. The
decomposition makes that failure mode visible instead of averaging
it away. Complexity: grouped counting via binary search,
O(G² · n log n) worst case over G segments.

## 4. Calibration metrics — declared probability scores ONLY

Refused (raising `ScoreTypeError`) for `score_type="ranking"`.
A calibration number attached to a ranking score is well-formed
arithmetic and meaningless statistics; the report format makes it
unrepresentable and the verifier rejects it even if resealed.

- **Brier**: (1/n) Σ (pᵢ − yᵢ)². Strictly proper; decomposable into
  calibration + refinement (decomposition not currently emitted).
- **Log loss**: −(1/n) Σ [yᵢ ln pᵢ + (1−yᵢ) ln(1−pᵢ)], p clipped to
  [ε, 1−ε], ε = 1e−15. Strictly proper; unbounded sensitivity to
  confident errors — that sensitivity is a feature for a security
  signal.
- **ECE**: with M equal-width bins B₁…B_M over [0,1]:

      ECE = Σ_m (|B_m|/n) · | acc(B_m) − conf(B_m) |

  Limitation (recorded in every report): ECE is binning-dependent.
  We fix equal-width bins and publish `n_bins`; the number is
  reproducible, not tunable after the fact. It is also a biased
  estimator at small n — the min-sample safeguard applies.

## 5. Label shift vs concept drift

Let reference window R (validation time) and current window C.

- **Label shift**: P(y) changed, P(score|y) unchanged. Detected when
  the Wilson 95% CIs of prevalence in R and C are disjoint.
- **Concept drift**: P(score|y) changed. Detected when either
  class-conditional two-sample Kolmogorov–Smirnov statistic

      D = sup_x | F_R(x) − F_C(x) |   (per class)

  exceeds a fixed threshold (default 0.15), or AUC degrades by more
  than a tolerance (default 0.05).

Decision rule: concept drift dominates (re-weighting cannot fix it);
label shift alone ⇒ prior correction suffices; below minimum samples
⇒ `insufficient_data`, no verdict. Limitations: fixed thresholds
rather than p-values (deliberate: reproducible, no distributional
assumptions); KS is insensitive in the tails; windows are assumed
exchangeable within themselves.

## 6. Prior-odds correction (no retraining)

Under pure label shift with training prior π and deployment prior π′,
a calibrated posterior p corrects in closed form:

    p′ = p·(π′/π) / [ p·(π′/π) + (1−p)·((1−π′)/(1−π)) ]

Equivalently: multiply the odds by the prior-odds ratio. Identity at
π′ = π (tested). Valid **only** when (a) the drift verdict is
`label_shift_only` and (b) the score is a validated probability.
This is the single-step form of the Saerens–Latinne–Decaestecker
EM adjustment; the full EM iteration is unnecessary when π′ is
measured directly from independently labelled outcomes.

## 7. Safeguards

- `min_samples` (default 30): segments below it report
  `insufficient_samples` and **no point estimates** — a small-n
  number in a report is a number someone will quote.
- Both classes required for AUC; single-class segments report
  prevalence (with CI) only.
- `label_source` must be `"independent"` with a note naming the
  source. Outcomes labelled by the scored system itself are refused
  at construction (`LabelSourceError`).

## 8. Sealing and independent verification

The report body is canonical JSON (sorted keys, separators `(",",":")`,
ASCII) hashed with SHA-256; the envelope is `{body, report_hash}`.
`tools/verify_validation.py` (stdlib only) recomputes the seal and
re-checks: count consistency, the decomposition identity, pair-share
sum, ranking/calibration honesty, safeguard compliance, and label
source — so an auditor's acceptance of the numbers never depends on
trusting this codebase.

## 9. Runtime coupling (and its deliberate limits)

`ValidationGuard` (env: `PV_VALIDATION_REPORT`):

- Global AUC below 0.60 ⇒ drift threshold multiplied by 0.80 —
  **tighten-only**, `min(configured, adjusted)`, applied by
  composition when constructing the engine; `decision.py` unchanged.
- Missing / expired / tampered / malformed report ⇒ configured
  threshold untouched + warning. Absence of validation is the status
  quo, never a bypass.
- Calibration findings ⇒ warnings only. They constrain how outputs
  may be *described*, never how enforcement behaves.
- L0–L4 have no API surface reachable from this module (tested).
