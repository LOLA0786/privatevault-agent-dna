# What We Do NOT Claim

PrivateVault AI (Pentaprime Solutions) · Decision Security Runtime · July 2026

This page exists because a vendor's claims should be as verifiable as
its cryptography. Where we can't back a claim with a test, a public
artifact, or a third-party attestation, we say so directly here
rather than leave it ambiguous.

## Certification

**We have not applied for SOC 2 Type II or ISO/IEC 27001
certification. Neither is in progress.** As a pre-seed company,
formal third-party attestation is a post-funding milestone, not a
current claim.

What exists today, verifiable directly:

- A standard-library-only, independently verifiable audit format —
  no dependency on our code to check our claims. See
  [drp-spec](https://github.com/LOLA0786/drp-spec) and
  `tools/verify_records.py`.
- 138 automated tests, run in CI on every commit
  ([workflow](https://github.com/LOLA0786/privatevault-agent-dna/actions)).
- Hashed API-key authentication (SHA-256; keys are never stored, only
  their hashes).
- Fail-closed enforcement: any internal fault — a buggy scorer,
  invariant checker, authorizer, or evidence source — becomes a
  deterministic BLOCK, never a silent pass or an unhandled crash.
- No production secrets in source control (git history has been
  scrubbed of a prior exposure and rotated; `PV_RECEIPT_SIGNING_KEY`
  and `PV_API_KEYS_FILE` are environment/file-based, never committed).

If a completed SOC 2 or ISO certification is a hard procurement gate
for your organization, we will tell you the honest timeline rather
than claim readiness we don't have.

## Determinism

**We do not claim proof-theoretic soundness.** Our deterministic
layers (L0 enterprise constraints, L1 behavioral invariants) are
evidence-checked predicates and capability set-membership/transition
contracts — not a formally verified rule system. The claim is
**replayability**: identical inputs against the same policy version
produce the same verdict, reproducible by an auditor from the record
alone, with zero model inference in the decision path. That is a
narrower, checkable claim, and we prefer it to a broader one we
couldn't stand behind.

## Deployment maturity

**We do not claim multi-writer production deployment today.** The
reference deployment is single-process. Chain state correctly
survives a process restart (test-covered — a prior version of this
runtime did not guarantee this, and we fixed and tested it before
claiming it). Concurrent multi-instance writes to one datastore are a
scoped next step, not a shipped property.

**We do not claim signature envelopes persist across restarts today.**
Decision and execution records do — restart-safety here is
independently tested. Signature envelopes are currently retrievable
for the producing process's lifetime; persisting them as a
first-class, restart-safe record kind is on our roadmap, not shipped.

## Capability grants

**We do not claim delegation chains, mid-session grant rescoping, or
approval-token binding are shipped.** What is shipped and tested:
grants with expiry, revocation, and cumulative budget, with failures
naming their specific condition (e.g. "grant expired," "grant revoked
by security@corp," "budget exceeded"). Revocation history is
reconstructable from the audit trail alone. Delegation and rescoping
are the next build.

## Behavioral accuracy

**We do not claim our drift-detection accuracy figures apply to your
environment out of the box.** Behavioral profiles in our reference
deployment and demos are trained on clearly-labelled synthetic
execution traces. Thresholds are synthetic-calibrated until profiled
on a customer's real execution history — which is explicitly the
first phase of our pilot process, not an afterthought.

## Multi-agent capability

**We do not claim cross-agent consensus, topology, temporal, and
authority invariants are wired into the live enforcement path today.**
This layer exists as a tested library (unit-tested, including a
BFSI multi-agent payment-swarm scenario mapped to named regulatory
controls) but is not yet composed into the single-agent runtime
described in our technical overview. Integrating it is scoped and
architecturally compatible — it slots in as one more deterministic
checker in the existing precedence order — but it is not a shipped
claim until it is.

## Compliance

**We do not claim compliance.** A signed, tamper-evident decision
record is evidence that a specific decision was made, when, under
what conditions, and why. It is not a substitute for your own
regulatory or legal analysis, and we will not represent it as one.

## Latency and benchmark figures

**We do not publish precise latency or throughput figures without a
reproducible methodology attached.** Where we haven't measured
something in a way we could show our work on, we don't cite a number
for it.

---

If something above changes — a certification starts, a feature ships,
a limitation is resolved — this page updates in the same commit as
the code that changes it. The git history of this file is itself part
of the audit trail.

PrivateVault AI (Pentaprime Solutions) · privatevault.ai
