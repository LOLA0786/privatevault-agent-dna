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
- 1175+ automated tests, run in CI on every commit
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

**Loop discovery does not infer hidden agent activity.** It deterministically
analyzes strict events supplied at the authority boundary and detects circular
delegation/approval, authorization reuse, malformed causal ancestry, and
recursive canonical actions. It does not prove collusion, discover actions
that bypass telemetry, or establish that bytes reached a remote peer; dispatch
witness and closure evidence remain separate controls.

## Offline Discovery Loop

**We do not claim discovered candidates are safe to deploy automatically.** A
`PROPOSE` result means that a policy candidate passed declared assertions,
additive replay, the configured divergence budget, a committed adversarial
corpus, and supplied structural probes. It still requires a named policy owner,
normal PR review, and the policy-change gate. The runner cannot install policy.

The priority score is a deterministic triage heuristic, not a learned score or
scientific validation metric. Wilson intervals describe only the committed
corpus. Synthetic or operator-authored attack/benign labels are not independent
ground truth and do not establish production detection accuracy. Optional
`pv-validation/1` results remain advisory-only. Experimental Hodge and
authority-reachability analyses do not gate proposals until their schemas and
independent verifiers are stable.

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

## Exact-byte egress (what the sidecar guarantees)

**`ExactByteHttpDispatcher`** with a sidecar-owned transport
(`agent_dna/connector/adapters/exact_byte_http.py`) is the production
how-you-actually-send path after mint. The deployment pins
`PV_EXECUTION_TRUST_BUNDLE_FILE` at startup. Callers cannot select a
trust root, a TLS peer identity, or a send callback at dispatch time.

Verification is **two-stage**. Stage 1 is offline: destination, wire
bytes, and non-peer fields are checked against the pinned bundle
**before any network connection is opened**. Credentials are bound to
an allowlisted destination and `credential_audience` next. Only then
does the sidecar open a **per-dispatch** TLS session. Stage 2 checks
the observed peer certificate DER against the authorization, consumes
the permit, transmits the frozen `bytes` object, stamps `observed_at`
after the body is written, signs the dispatch witness, stamps
`closed_at` after the HTTP response is observed, and signs closure
with that status (`tests/connector/test_exact_byte_http.py`,
`tests/connector/test_sidecar_tls.py`).

When egress is routed through the production sidecar, it guarantees
(in order):

- serialize / freeze the outbound buffer;
- offline-verify the execution authorization (no socket yet);
- bind credentials only if destination and audience are allowlisted;
- TLS handshake on a connection owned by that dispatch; peer identity
  is the authenticated certificate DER;
- verify the observed TLS peer against the authorization;
- atomic single-use consume (at-most-once: a burned permit is not
  retried);
- transmit that same `bytes` object;
- only after a completed send: sign a dispatch witness and closure
  over the body, TLS peer, and HTTP status the sidecar independently
  observed.

Outcomes: `NOT_SENT` / `CONTROL_FAILURE` (send never began);
`EXECUTED` (verified witness + closure); `INDETERMINATE` after
transport invocation begins (`tool_executed=None`, `retryable=False`).
An arbitrary `SendFn` is test-only and does not prove bytes on the wire.

This class is an **in-process sidecar**. In-process is not complete
mediation. Complete mediation requires deploying it as a separately
isolated **sole-egress** service plus network policy that denies the
agent any other outbound path.

**Integrators must still:**

- route every consequential egress through this sidecar (or another
  adapter that passes `tests/test_adapter_conformance.py`);
- keep the witness signing key independent of the EA mint key;
- treat `INDETERMINATE` as a burned permit (mint again — we do not
  auto-retry);
- pin `PV_EGRESS_ALLOWED_DESTINATIONS` and
  `PV_EGRESS_ALLOWED_AUDIENCES` before attaching upstream credentials;
- enforce sole-egress + host network policy; this library cannot stop
  a raw socket that never calls the dispatcher.

**We still do not claim complete mediation** for effects that never
call the sidecar (see below).

## Compliance

**We do not claim compliance.** A signed, tamper-evident decision
record is evidence that a specific decision was made, when, under
what conditions, and why. It is not a substitute for your own
regulatory or legal analysis, and we will not represent it as one.

## Execution authorization binding residuals

**`POST /v1/authorize` now refuses to mint without a sealed ALLOW**
referenced by `decision_id` and/or `record_hash`, with distinct reason
codes for missing reference, absent decision, non-ALLOW, agent
mismatch, and digest/action mismatches
(`tests/test_authorize_binding.py`). **Single-use consumption is
recorded in a durable SQLite ledger** keyed by
`execution_authorization_id`, claimed atomically on successful verify
(`tests/test_consume_ledger.py`).

## Caller-controlled enforcement residuals (F-03 / F-04 / F-05)

**Production composition attaches a deny-all `GrantRegistry` when
`PV_GRANTS_FILE` is unset** (not `authorizer=None`). Development
(`PV_ALLOW_NO_AUTH`) uses `OpenAuthorizer` and records
`authorization_mode=open` in decision evidence — operator opt-in, not
a request flag (`tests/test_caller_controlled_enforcement.py`).

**`PV_CROSS_AGENT_REQUIRE_EXECUTION_ID`** (default off; on in the
platform compose profile) fails closed for declared tool-target
capabilities without `execution_id`. **`PV_LOOP_EVENTS_REQUIRED`**
(same) refuses `/v1/authorize` without `security_events`.

Residual gaps we still do not claim closed:

- **Require-execution-id and loop-events-required default OFF** outside
  the platform profile for compatibility. An operator who leaves them
  off still allows callers to omit correlation / loop events; the
  decision evidence and composition manifest record that posture.
- **Organisation is not a DecisionRecord field (drp/0.1 / 0.2).** Mint
  checks `organisation_id` against the pinned trust bundle and
  `agent_id` against the sealed record + authenticated caller.
- **Wire and peer digests are not sealed at decide time.**
- **Library verify without a `consume_ledger` remains caller-attested**
  for consumption.
- **One ALLOW may mint multiple permits** until each permit's id is
  consumed (unless a later mint ledger is merged).
- **Complete mediation** remains unsolved: an agent that never calls
  `/v1/decide` is not controlled by these flags.

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

## Inline MCP gateway (Phase 2) — mediated egress, not complete mediation

**We claim mediated egress with detectable bypass for the MCP gateway
transport (`agent_dna/gateway/`), not complete mediation.**

What is shipped and tested (`tests/gateway/`):

- The client connects to the gateway as if it were the MCP server; the
  gateway holds upstream credentials and evaluates every `tools/call`,
  `resources/read`, and `resources/subscribe` before any bytes are written
  upstream. `resources/*` that read or subscribe are treated as
  consequential and gated through the same decide path
  (`tests/gateway/test_protocol_hardening.py`).
- DENY / REQUIRE_APPROVAL return MCP errors and never forward.
- Exact-byte binding on this transport: the gateway freezes the
  Content-Length–framed JSON-RPC payload it will write, digests those
  bytes with `sha256_bytes_digest`, and writes only that frozen buffer
  (`tests/gateway/test_mediation_adversarial.py`).
- In-flight `tools/call` requests are correlated by JSON-RPC id, not by
  arrival order. A response binds to the decision for *that* id. An id
  never sent is rejected and matches nothing. A duplicate client id
  while a call is in flight is refused. Duplicate ids from a malicious
  upstream do not cross-bind two decisions. Server-initiated requests
  and notifications arriving mid-call are not treated as responses
  (`tests/gateway/test_protocol_hardening.py`).
- `sampling/createMessage` is refused (never forwarded), including when
  the untrusted upstream initiates it. That method is a path from the
  server into the client's model.
- Methods not in the enumerated gated / passthrough / refused sets fail
  closed: they are not forwarded and the exact method name is recorded.
- Frame reading is bounded and mode-explicit (`tests/gateway/test_framing.py`):
  header ≤ 8 KiB, body ≤ configurable `max_message_bytes` (default 8 MiB),
  JSON nesting ≤ `max_json_depth` (default 32), Content-Length framing
  only in production; trailing bytes after a frame are retained for
  pipelining; newline framing is test-only. The same size and depth
  caps apply to upstream bodies, not only client frames.
- TLS certificate verification is on by default for HTTP/SSE; starting
  with verification disabled requires the operator flag
  `allow_insecure_tls`. Cross-origin HTTP redirects are refused (they
  would substitute the sealed dispatch destination). An SSE/HTTP body
  that never ends hits the byte bound.
- Upstream process death, restart (new principal / identity), and
  graceful shutdown with calls in flight leave in-flight work
  indeterminate — never sealed `ok`. A client reconnect mints a new
  session and cannot complete another session's ids.
- Upstream timeout or client disconnect after the request was written
  records an execution outcome with DRP status `indeterminate` (detail
  still carries the `INDETERMINATE:` prefix for operators). It is not
  auto-retried and is never sealed as `ok`. An offline verifier can
  distinguish this from `error`. Allowed completions also bind
  `response_digest` (sha256 of the exact bytes returned to the client)
  on that same execution event when a response was witnessed.

Residual gaps we explicitly do **not** claim closed:

- **Bypass by reconfiguration:** an agent that already holds the
  upstream credential and points the MCP client at the real server is
  still unmediated. What is now fail-closed: the gateway always
  attributes its own session (`X-PV-Gateway-Session` /
  `PV_GATEWAY_SESSION_ID`); if the operator/upstream reports
  unattributed sessions, new sessions and in-flight forwarding stop
  (`MCP_BYPASS_DETECTED`). Without that report, bypass remains
  invisible. Complete mediation of the host is not claimed.
- **Non-MCP egress** other than the named `https-egress` transport
  (raw sockets, other protocols, cloud metadata) remains outside this
  gateway. `https-egress` covers one operator-named HTTPS URL with the
  same freeze/decide/verify story; it is not a generic HTTP forward
  proxy. Production entry is
  `python -m agent_dna.gateway --https-egress URL --capability CAP`
  serving `POST /egress` (not MCP JSON-RPC). Callers cannot retarget
  the named URL. Same-origin redirects are re-decided once; hop budget
  exhaustion is first-class `indeterminate`.
- **Exact-byte binding** is for the MCP gateway transport and the
  named HTTPS egress transport. The decide API still does not seal
  arbitrary wire digests at decide time for other callers.
- **HTTP/SSE residuals:** `http://` requires the operator flag
  `allow_insecure_http` (HTTPS-only by default). Same-origin redirects
  are re-decided (not followed silently) with a hop budget of 1;
  cross-origin redirects are refused. HTTP upstream restart at the
  same URL is still not observed as a new principal. SSE is still a
  byte bound, not a multiplexed session. Server-initiated
  notifications (progress, logging, elicitation, `roots/list`) are
  recorded and refused rather than delivered to the client.
- **Passthrough without a mintable decision** is limited to
  `initialize`, `notifications/initialized`, `notifications/cancelled`,
  `ping`, `tools/list`, `prompts/list`, `resources/list`,
  `resources/templates/list`, `logging/setLevel`. `prompts/get` is now
  gated. Production constructors set `undeclared_tool_policy=block`
  (no catalog or undeclared name → not forwarded). In-process tests
  default to `finding` unless the hardened flag is set.
- **`sampling/createMessage` is refused, not gated.**
- **Correlation residuals:** unmatched/malformed frame floods can
  delay pairing until timeout. `resources/subscribe` freezes only
  `params.uri`.
- **DRP `indeterminate`** is a first-class execution status; `ok` is
  never inferred. Optional `response_digest` is hashed with the
  execution payload when present. The independent verifier pin in
  this repo must stay in lockstep with drp-spec (update both).
- **Out-of-process production:** `from_stdio_command`, `from_http_url`,
  and `from_https_egress` are the production constructors; in-process
  mocks require `_test_allow_inprocess`. Running `python -m
  agent_dna.gateway` still shares a machine with the operator — it is
  a separate process, not a hardware enclave.
- **Legacy** `experimental/legacy_mcp/` remains quarantined.
- **Framing residuals:** dribble-liveness until read timeout; no
  Unicode normalization before digest.

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
nothing about effects we were never asked to decide. The inline MCP
gateway narrows the window for MCP tool calls when the client is
configured to use it; it does not close the window for agents that
bypass that configuration.

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

## Revocation is not in the offline evidence

Revocation is enforced at runtime (`agent_dna/grants.py`): a revoked grant
blocks with a named reason, and revocation history reconstructs from decision
records. It is **not** represented in `pv-authority-receipt/0.1`. An offline
verifier can confirm signatures, chain linkage, delegation depth, capability
containment and validity windows at decision time; it cannot confirm that no
grant in the chain had been revoked. Revocation status is therefore attested
by the runtime, not independently verifiable from the receipt. Planned for
receipt v0.2 as a decision-time-pinned status digest.

## Signing defends against alteration, not against a compromised signer

Signed records detect post-signing alteration and independent tampering. They
do **not** defend against privileged manipulation performed by the operator at
signing time. An operator who signs a false record produces a record that
verifies correctly. Defending against this requires HSM- or TEE-backed signing
with attestation, which is roadmap, not shipped. "Verifiable without trusting
the operator" is therefore too strong: the correct claim is "verifiable
without trusting the operator's later handling of the evidence."

## Role-based influence control is not on the /v1/decide path

`definitional_engine()` — the CABI engine attached to `/v1/decide` — runs
dual-control and structural approval contradictions only. `AuthorityInvariant`
(role-level influence allowlisting) is a learned family and is not attached
there, because an untrained allowlist would block ordinary traffic. It is
enforced on the library path via `default_engine()`, where an unresolved
source role is a hard breach, an unresolved target role escalates for review,
and an untrained role model abstains. Deployments requiring role-based
influence control on the HTTP decide path must configure it explicitly.

## One ALLOW can mint more than one execution permit

`/v1/authorize` binds mint to a sealed ALLOW decision and refuses without one.
Consumption is enforced per `execution_authorization_id` via a durable ledger,
so no permit verifies twice. There is currently no per-decision mint limit: a
single ALLOW can produce multiple distinct single-use permits. Deployments that
require one decision to authorize exactly one execution must enforce that
above this layer.
