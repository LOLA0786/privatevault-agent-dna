# 0011 — Every claim is pinned to a named test, count enforced in CI

Status:     accepted
Date:       2026-07-26
Commit:     3936683247ea7b5ace866af8c04b8ee44731afa6
Pinned by:  tests/test_claim_counts.py::test_documented_test_count_matches_reality

## What forced the decision
The README said 452 tests, WHAT-WE-DO-NOT-CLAIM said 561, the
flagship demo printed 286, and the suite collected far more. Nobody
lied on purpose. The count lived in prose, prose has no build step,
and the documents whose job is trustworthiness were the ones that
drifted.

The tempting alternative is "we'll update the number when we
remember," or an exact-equality guard that goes red whenever the
Rust wheel is installed locally and not in Python CI. The first
equality design compared a subprocess collection to a different
environment than the run in progress, so CI and laptops disagreed
with no way to see why.

## The decision
A published test-count claim is a floor, checked against
`session.testscollected` of the run actually in progress. README,
WHAT-WE-DO-NOT-CLAIM, and the composed-line demo must agree with
each other and must not overstate the suite. Staleness of more than
forty extra tests fails the build so the number cannot rot in the
other direction either. `tools/prove.py` is the CI claim gate: it
re-runs the suite, adversarial corpus, and verifiers and seals a
proof-of-run. A sentence without a named test belongs in
WHAT-WE-DO-NOT-CLAIM, not in a claim.

## What this costs us
Adding tests is a docs edit in the same change. The floor-plus-
tolerance means the printed number lags reality by up to forty.
Environments without the Rust wheel collect fewer nodes; the claim
must remain a floor that those environments still meet. prove.py is
slow; it is still the gate.

## What would make us revisit
Generating the number from collection at docs-build time so prose
cannot drift, with the same over-claim prohibition. Raising
`STALENESS_TOLERANCE` until the guard never fires is not a trigger.
