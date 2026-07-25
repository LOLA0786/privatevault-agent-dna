# PrivateVault — Decision Security Runtime
## Technical Overview: Runtime Enforcement for Autonomous Agents

Prepared for review · Updated July 2026 · PrivateVault AI (Pentaprime Solutions)

---

## 1. The layer this covers

Governed AI platforms define what agents are allowed to do. Runtime
enforcement is the separate layer that stops an agent from doing
something else — before the action executes, with proof afterward.

Most governance stacks handle policy definition, catalogs, and
post-hoc audit. The gap is pre-execution: an agent under prompt
injection, a compromised orchestration layer, or ordinary drift will
attempt actions its governance layer never sanctioned, at machine
speed, often irreversibly. Log aggregation discovers this after the
wire transfer clears.

This is an **operational / technology risk control**, not a model
risk control. It does not evaluate whether a model's outputs are
statistically sound; it governs what the agent is permitted to
*execute*, deterministically, and produces evidence that holds up
independently of the vendor. Where agentic behavior sits outside
classic model-validation scope, the deterministic layers below are
what a risk function can hold onto.

## 2. Architecture: seven-level precedence

Every agent action is evaluated through a strict, sequential,
short-circuit precedence order. First violation terminates. Every
decision record carries a `triggered_by` field naming the level that
decided — the audit narrative is a queryable attribute, not an
inference.

    L0  Enterprise constraints   deterministic, evidence-checked   -> BLOCK
    L1  Behavioral invariants    deterministic contracts           -> BLOCK
    L2  Multi-agent consensus    evidence-gated, signed voting     -> REQUIRE_APPROVAL
    L3  Capability grants        deterministic authorization       -> REQUIRE_APPROVAL
    L4  Economics                cost/ROI anomaly check            -> REQUIRE_APPROVAL
    L5  Learned drift            probabilistic, advisory           -> REQUIRE_APPROVAL
    L6  Trusted baseline                                           -> ALLOW

**The non-negotiable property:** a deterministic DENY is final. The
learned model (L5) can only raise scrutiny — escalate an ALLOW to
REQUIRE_APPROVAL — never lower it. The security boundary is
deterministic and auditable; machine learning adds earlier warning,
not a new bypass.

**"Deterministic," defined precisely:** L0 comprises evidence-checked
predicates — pure functions over caller-supplied enterprise evidence
(amount conservation against invoice state, canonical-target identity
across user request / planner / tool call, approval-token presence).
L1 comprises capability set-membership and transition contracts.
Neither claims proof-theoretic soundness; the claim is
**replayability**: same inputs, same verdict, reproducible by an
auditor from the record alone, with zero model inference in the path.

L0 is additionally **evidence-honest**: invariants whose required
evidence is absent are reported as *skipped*, never silently passed
or failed. Every other level (L2-L4) follows the same rule — absent
evidence skips that specific check, it never counts as passing.

**The precedence order itself is not just documented** — it is a
committed, hash-pinned contract (`spec/contracts/precedence-order.json`)
that continuous integration verifies against the actual code path on
every push. If the real evaluation order ever diverges from the
committed contract without a deliberate, reviewed update, the build
fails.

## 3. Multi-agent consensus (L2)

For actions requiring multi-agent agreement, callers supply signed
votes: `{agent_id, vote, signature, message_hash}`. Signatures are
HMAC-based; an unsigned or forged vote contributes zero weight to the
quorum calculation — proven directly (`test_forged_signature_is_rejected`,
`test_byzantine_third_cannot_override_honest_two_thirds`). A quorum
shortfall escalates to REQUIRE_APPROVAL; it can never independently
BLOCK — a disagreement among agents is a governance signal, not a
proven security violation the way a tampered amount is.

This level is evidence-gated like L0: if no vote evidence is
supplied, the check is skipped and the action proceeds through the
remaining levels normally — single-agent actions are unaffected.

## 4. Capability grants (L3)

Authorization is grant-based, not allowlist-based. A grant carries an
issuer, optional expiry, and optional cumulative budget. Failures
name their specific condition:

    "grant expired"
    "grant revoked by security@corp"
    "budget exceeded (12,000.00 > 10,000.00)"

Because every decision is recorded with its reason, **revocation
history is reconstructable from the audit trail alone** — decisions
made before and after a revocation are distinguishable in the record
stream, hash chain intact. (Delegation chains, mid-session rescoping,
and approval-token binding are roadmap.)

## 5. Economics (L4)

Two independent, evidence-gated checks: a cost-ratio anomaly (claimed
cost vs. this agent's historical average) and an ROI floor (claimed
cost vs. a supplied business-value estimate). Deterministic, never
blocks — an efficiency signal, not a security violation, so its
ceiling is REQUIRE_APPROVAL like the other advisory-tier levels.

## 6. Decision Runtime Protocol (DRP): the evidence layer

Every decision is serialized as a sealed record under an open wire
format (drp/0.1):

**DecisionRecord** — one per authorization decision. SHA-256 over
canonical JSON; per-agent hash chain (genesis 64 zeros, or an
external provenance anchor for chains that originate from an upstream
transformation batch); the chain link is *inside* the digest, so any
signature over the record hash covers the record's position in
history. Raw action arguments are never stored — a digest only.

**ExecutionEvent** — at most one per decision, reporting what
actually executed. Hash-anchored to its decision: forging or
retro-fitting outcomes breaks the anchor.

**Ed25519 signing** — a detached envelope signs the record hash
directly. Because the chain link is inside the hash, a signed record
cannot be silently re-chained: an attacker can re-seal a moved record
validly, and the original signature still disowns it.

**Independent verification** — an independent Python tool verifies chain integrity with no dependency on this
codebase:

| Attack on the log                       | Detection               |
|-------------------------------------------|--------------------------|
| Edit any field of any record              | record-hash mismatch     |
| Delete or reorder records                 | per-agent chain break    |
| Forge an execution result                 | anchor mismatch          |
| Runtime claims BLOCK, action ran anyway   | ENFORCEMENT DIVERGENCE   |

The format, schemas, test vectors, and verifier are published as an
open specification (github.com/LOLA0786/drp-spec, Apache-2.0 /
CC-BY-4.0), with a crosswalk to the CSA/CSAI AARM working-group
specification.

## 7. Demonstrated behavior (actual output)

One agent stream through all seven levels — verbatim runtime output:

    L0  enterprise constraint  — amount tampered 5,000 -> 49,000
        -> BLOCK             trigger=uaal_constraint signed=Y
    L1  behavioral invariant   — forbidden bulk export
        -> BLOCK             trigger=invariant      signed=Y
    L2  multi-agent consensus  — finance agent dissents on settlement
        -> REQUIRE_APPROVAL  trigger=consensus      signed=Y
    L3  capability grant       — ungranted wire transfer
        -> REQUIRE_APPROVAL  trigger=authorization  signed=Y
    L4  economics              — cost 25,000x historical average
        -> REQUIRE_APPROVAL  trigger=economics      signed=Y
    L5  learned drift          — honest payment, novel for this agent
        -> REQUIRE_APPROVAL  trigger=drift          signed=Y
    L6  baseline                — normal in-profile CRM read
        -> ALLOW             trigger=baseline       signed=Y

    chain verified : True   divergent : 0   signed envelopes : 7
    independent verifier : VERDICT: PASS

    ATTACK: re-chain a signed record
    record re-seals cleanly : True
    signature still binds   : False

Three details worth attention:

1. **Precedence is observable.** Each scenario is caught by a
   different level, each attributed by name — the audit narrative is
   a field, not an inference.
2. **Layers disagree correctly.** The honest payment passed every
   deterministic check but was escalated at L5: this agent had never
   paid invoices before. Deterministic says fine; behavioral says get
   a human. That interplay is the design.
3. **The re-chain attack fails** despite producing an individually
   valid record: the signature pins the original hash, which pins the
   original history.

## 8. Enterprise integration

**HTTP enforcement surface.** `POST /v1/decide` — the status code is
the enforcement signal: `200` allow, `202` require-approval, `403`
block. API-key authenticated (hashed at rest). Every decision is
persisted before the response returns. Companion endpoints:
`/v1/outcome`, `/v1/envelope/{hash}`, `/v1/blocked`, `/v1/divergent`,
`/v1/lineage/{id}`, `/v1/verify`, `/v1/audit/export`.

**MCP.** The same composed line is exposed as six MCP tools
(`pv_decide`, `pv_report_outcome`, `pv_verify`, `pv_lineage`,
`pv_blocked`, `pv_divergent`).

**Evidence model.** Enterprise context is supplied per-request by the
caller. A documented evidence-integration contract
(`spec/contracts/evidence-integration.md`) specifies the exact shape
each level consumes, distinguishing shipped keys from named-but-
unbuilt ones, so a future connector to an internal system integrates
against a stable target.

**Framework-agnostic.** An intent adapter maps
`AgentIntent(actor, verb, target, parameters)` to the internal action
contract.

**Deployment.** Docker/compose; SQLite (WAL) persistence, the store
strictly an index over the canonical audit format. Fail-closed at
both the engine and API layers: any internal fault produces a
deterministic BLOCK, never a silent pass or unhandled crash — verified
by fault-injection tests at each external dependency seam. The
service survives being killed mid-stream: chain state rebuilds from
the store on restart. Current reference deployment is single-process;
multi-writer is specified for the next phase. CI runs the full suite
plus the spec vectors on every push.

## 9. Status — precise, by design

**Shipped and tested (561 automated tests):** seven-level precedence
engine including multi-agent consensus and cost/ROI economics;
behavioral drift scoring; grants with expiry/revocation/budget; sealed
hash-chained records with external-provenance anchoring for chain
origins; Ed25519 signing; execution anchoring; enforcement-divergence
detection; independent stdlib verifier; HTTP + MCP surfaces; API-key
authentication; fail-closed enforcement; a hash-pinned, CI-guarded
precedence-order contract; open spec with pinned test vectors.

**In development:** delegation chains and approval-token binding for
L3; signature-envelope persistence as a first-class record kind;
Postgres-interface storage; multi-writer deployment.

**Research track:** formal intent verification; cross-agent
behavioral invariants beyond consensus — topology, temporal ordering,
authority (`multi_agent/` — built and unit-tested as a library, not
yet composed into the serving path).

**Calibration honesty:** behavioral profiles are trained on
clearly-labelled synthetic traces; drift thresholds are
synthetic-calibrated. Production deployment profiles on the
customer's real execution traces — the explicit first phase of any
pilot.

## 10. The question for Fusion

Where does Fusion draw the line between defining what agents may do
and enforcing, pre-execution, that they do nothing else — and what
does Fusion's audit story require when an agent's action and its
authorization disagree?

If the enforcement layer described here is adjacent to that line,
everything referenced above is available for direct review:

- Runtime + demos + 198-test suite: private repository, access
  available on request
- DRP specification — schemas, test vectors, independent chain and signature verifier:
  public, github.com/LOLA0786/drp-spec
- The composed demo (§7): `examples/composed_line_demo.py`

A working session can run the composed line against scenarios of your
choosing.

---
Chandan Galani · Founder, PrivateVault AI · Mumbai
