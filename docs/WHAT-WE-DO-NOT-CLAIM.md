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

- An independent audit verifier with standard-library chain mode and
  optional trusted Ed25519 verification. Neither mode imports the producing
  runtime. See [drp-spec](https://github.com/LOLA0786/drp-spec) and
  `tools/verify_records.py`.
- Signature verification was self-attested before v0.3.0: the public key
  inside each envelope was accepted without an external trust anchor.
  v0.3.0 added explicitly pinned keys across the runtime, API, manifests and
  independent verifier.
- 655+ automated tests, run in CI on every commit
  ([workflow](https://github.com/LOLA0786/privatevault-agent-dna/actions)).
- Hashed API-key authentication (SHA-256; keys are never stored, only
  their hashes).
- Fail-closed enforcement: any internal fault — a buggy scorer,
  invariant checker, authorizer, or evidence source — becomes a
  deterministic BLOCK, never a silent pass or an unhandled crash.
- MCP support, two distinct layers: (1) 6 advisory tools over the
  composed decision line (pv_decide, pv_report_outcome, pv_verify,
  pv_lineage, pv_blocked, pv_divergent); (2) transport-level
  enforcement — any FastMCP server wrapped by our connector routes
  EVERY tools/call through the full precedence line before the tool
  executes, with per-session agent identity over streamable HTTP
  (Authorization bearer) and signed refusals in-band
  (`tests/connector/`). Not yet load-tested under high concurrent
  MCP client counts.
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

**Multi-writer safety to one datastore is now shipped and tested**
(atomic chain-head transactions, thread-local SQLite connections
after a real shared-connection cursor race was caught by our own
suite, root-caused, and pinned —
`tests/test_multi_writer_safety.py`,
`tests/test_connection_thread_safety.py`). Chain state survives
process restart (test-covered). **We still do not claim horizontally
scaled multi-instance deployment**: no load-balancer story, no
concurrent-load benchmark, no shared-nothing design decided.

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

**Multi-agent consensus (signed, trust-weighted quorum voting) is
wired into the live precedence order** as an evidence-gated level:
absent vote evidence, the check is skipped, never silently passed; a
quorum shortfall escalates to REQUIRE_APPROVAL, it can never
independently BLOCK. Forged and unsigned votes are proven to
contribute zero weight (`tests/test_secure_quorum.py`,
`tests/test_consensus_checker.py`).

**Cross-agent invariants (topology, temporal-ordering, authority)
are now wired into the live connector enforcement path** as an
escalation-only post-decision check: a violating interaction window
can escalate a verdict (allow -> block/require_approval), never relax
one, and escalated verdicts are chained and signed
(`tests/connector/test_cross_agent.py` — maker!=checker dual-control
proven through the connector). Honest scope of that claim:

- **Correlation is declared, not inferred.** Cross-agent evaluation
  requires the caller to supply an `execution_id`; uncorrelated calls
  get the full single-agent precedence line and breakers, but no
  cross-agent evaluation. We do not claim to detect coordination
  across calls we were not told are related.
- **Group circuit-breaker membership is declared config, not
  behavioral inference.** The distributed-drain trip (N agents
  jointly exceeding a group volume cap, each individually under its
  per-agent cap — `tests/test_group_breaker.py`) enforces stated
  swarm structure. Detecting undeclared coordination is a
  drift/anomaly problem, and we do not claim the deterministic
  breaker solves it.
- **Agent roles and tool targets are declared config.**

## Connector & transport security

**We do not claim transport encryption.** Connector identity binds
agents to API keys carried as HTTP bearer headers; the connector does
not terminate TLS. Deploying without TLS in front of it sends keys in
plaintext. TLS is the deployment's responsibility and we say so
rather than imply otherwise.

**We do not claim live key rotation or revocation.** Key changes are
registry-file reloads. No secrets-manager integration, no rotation
mechanism (see PRODUCTION-HARDENING.md).

**Two private third-party SDK surfaces are load-bearing** in the MCP
adapter (`FastMCP._tool_manager`, `mcp.shared._httpx_utils`), pinned
to mcp>=1.0 and guarded by integration tests that fail loudly on an
SDK surface change (`tests/connector/test_mcp_adapter.py`,
`tests/connector/test_mcp_http_identity.py`). A future SDK major
version will break tests, not enforcement.

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

## OPA integration boundaries

We DO ship: authenticated (bearer/mTLS) REST evaluation against a
customer's OPA on the enforcement path, fail-closed on every failure
mode, a bounded total latency budget, rule identity written into the
sealed record when the customer's Rego provides it, and a degraded
capability-allowlist bundle for air-gapped operation.

We do NOT claim: OPA cluster/HA failover, bundle signature
verification, or local Rego evaluation. The bundle path is a
capability allowlist, not a policy engine -- it can deny, it can clear
an explicitly allowlisted capability, and it fails closed on anything
else. If a customer's Rego does not return a rule identifier,
`policy_id` in the decision record is null; we do not infer one.

## Quarantined code (2026-07 audit)

We do NOT claim adversarial benchmark results. The former
`security_validation` suite contained adversaries that graded
themselves without invoking the runtime; it is quarantined in
`experimental/` and its numbers should be treated as void. The honest
adversarial harness is `tools/run_adversarial.py` against
`spec/adversarial/`, which exercises the real engine.

We do NOT claim a profile marketplace, PostgreSQL cluster store,
OPA cluster/TLS/version tooling, or a dashboard product. Placeholders
for these live in `experimental/` (dashboard: `dashboard/`, a UI
scaffold) and are excluded from the package;
`tests/test_quarantine.py` enforces the exclusion.

If something above changes — a certification starts, a feature ships,
a limitation is resolved — this page updates in the same commit as
the code that changes it. The git history of this file is itself part
of the audit trail.

PrivateVault AI (Pentaprime Solutions) · privatevault.ai

## Model validation (pv-validation/1)

**We do not claim the advisory drift scorer is validated on real
production traffic.** The validation machinery (Wilson intervals,
AUC decomposition, calibration metrics, drift distinction — see
`docs/VALIDATION-MATH.md`) is itself fully tested and independently
verifiable, but until a customer pilot supplies independently
labelled real outcomes, any published report is computed on synthetic
labels and says so in `label_source_note`. We also do not claim ECE
is binning-independent (it is not; `n_bins` is recorded), nor that
segment metrics below the minimum sample count exist at all — they
are withheld by design. The validation layer can only ever TIGHTEN
enforcement at the drift level; we make no claim that it improves
detection, only that it honestly measures the advisory signal and
refuses to describe ranking scores as probabilities.

## Complete mediation (the window, not the door)

**We do not claim PrivateVault prevents sandbox escape or mediates
actions that never pass through it.** PrivateVault is a reference
monitor for actions submitted to it. It is tamper-evident (hash
chains) and independently verifiable (stdlib verifier), but the third
reference-monitor property -- complete mediation, that *every* real
external effect is submitted for a decision -- is not something a
library inside the agent's own process can provide. An agent that
opens a raw socket, spawns a subprocess, reaches a cloud metadata
endpoint, or otherwise produces an external effect without routing it
through the decision path is not mediated, and our hash chain proves
nothing about effects we were never asked to decide.

Stated as the property we are working toward, and do NOT yet claim:

    ExternalEffect(x) => exists! d : ALLOW(d) AND Binds(d,x) AND Fresh(d)

"No external effect may occur without exactly one prior, valid ALLOW
decision bound to that exact action." The universal quantifier over
external effects is a *completeness* claim, and completeness is
provable only by an observer OUTSIDE the agent -- infrastructure
containment (network namespace / eBPF egress capture, syscall
filtering, a sidecar that sees real traffic) that reconciles observed
effects against the decision log. Integrity (which we have) is not
completeness (which requires that observer) is not truth (that the
producer recorded every real action faithfully).

Concretely, the 2026-07 Hugging Face incident -- an agent escaping an
evaluation sandbox via code execution, credential harvesting and
lateral movement -- is NOT an incident PrivateVault is proven to
stop, because no enforcement layer sat in the action path. Our
adversarial corpus demonstrates that the *action patterns* (target
drift, credential access, lateral movement, external egress) are
refused when submitted to the ladder. It does not demonstrate
complete mediation, and we do not claim it until an independent
infrastructure observer is built and shown to reconcile real external
effects against the ALLOW log.

### Evidence handling is fail-closed for sensitive actions

A related, narrower fix (shipped): L0 evidence handling is
three-state. Present evidence is evaluated; absent evidence for an
*optional* invariant is skipped honestly; absent evidence for a
*mandatory* invariant on a *sensitive* capability class (credentials,
infra exec, external egress, role assumption) is a BLOCK
(missing_required_evidence). This closes a fail-open in which an agent
could defeat the identity-preservation check simply by omitting its
evidence. The scope is deliberate: missing identity evidence blocks
only where an unstated intent is itself anomalous, so ordinary
actions are not forced to carry planner evidence.

## Authority Provenance v0.1-experimental

**Revocation.** v0.1 provides no emergency revocation. Maximum
stale-authority exposure is bounded by the configured grant TTL. Expiry limits
exposure; it does not revoke an already-compromised grant.

**Completeness.** The receipt chain proves internal continuity within a
supplied sequence. It does not detect truncation, deletion of trailing records,
or an alternative fork presented by the operator. Completeness requires an
externally retained signed checkpoint in v0.2.

**Replay.** The receipt is cryptographically bound to a request instance.
Execution-time idempotency state prevents reuse. Offline scanning detects
duplicates only within the supplied record set.

**Obligations.** v0.1 verifies that obligations were not shed across
delegation. It does not prove an obligation was satisfied at decision time.
That requires signed approval evidence in v0.2.

**Trust bundle.** The bundle is pinned out of band and unsigned in v0.1. An
operator with write access to the bundle can retroactively make a forged
historical receipt verify. Signed, versioned bundles are v0.2.

**Verifier independence.** The verifier is independent of the PrivateVault
runtime and hosted service. It is not independent of a language runtime, a
crypto library, or an operating system. We do not say zero trust in the
codebase.

**Learned layer.** The drift scorer remains trained on synthetic traces. It is
advisory and never blocking until real execution traces are available.
