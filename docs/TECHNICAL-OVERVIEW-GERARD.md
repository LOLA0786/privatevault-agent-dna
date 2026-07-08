# PrivateVault — Decision Security Runtime
## Technical Overview: Runtime Enforcement for Autonomous Agents

Prepared for review · July 2026 · PrivateVault AI (Pentaprime Solutions)

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

## 2. Architecture: five-level precedence

Every agent action is evaluated through a strict, sequential,
short-circuit precedence order. First violation terminates. Every
decision record carries a `triggered_by` field naming the level that
decided — the audit narrative is a queryable attribute, not an
inference.

    L0  Enterprise constraints   deterministic, evidence-checked   -> BLOCK
    L1  Behavioral invariants    deterministic contracts           -> BLOCK
    L2  Capability grants        deterministic authorization       -> REQUIRE_APPROVAL
    L3  Learned drift            probabilistic, advisory           -> REQUIRE_APPROVAL
    L4  Trusted baseline                                           -> ALLOW

**The non-negotiable property:** a deterministic DENY is final. The
learned model (L3) can only raise scrutiny — escalate an ALLOW to
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
or failed. Unverifiable never masquerades as verified.

## 3. Capability grants with lifecycle

Authorization at L2 is grant-based, not allowlist-based. A grant
carries an issuer, optional expiry, optional cumulative budget, and a
revocation state. Failures name their condition:

    "grant expired"
    "grant revoked by security@corp"
    "budget exceeded (12,000.00 > 10,000.00)"

Because every decision is recorded with its reason, **revocation
history is reconstructable from the audit trail alone** — decisions
made before and after a revocation are distinguishable in the record
stream, hash chain intact. (Delegation chains, mid-session rescoping,
and approval-token binding are roadmap; see §7.)

## 4. Decision Runtime Protocol (DRP): the evidence layer

Every decision is serialized as a sealed record under an open wire
format (drp/0.1):

**DecisionRecord** — one per authorization decision. SHA-256 over
canonical JSON; per-agent hash chain (genesis 64 zeros); the chain
link is *inside* the digest, so any signature over the record hash
covers the record's position in history. Raw action arguments are
never stored — a digest only, which matters for data residency.

**ExecutionEvent** — at most one per decision, reporting what
actually executed. Hash-anchored to its decision: forging or
retro-fitting outcomes breaks the anchor.

**Ed25519 signing** — a detached envelope signs the record hash
directly (never a re-canonicalized body). Because the chain link is
inside the hash, a signed record cannot be silently re-chained: an
attacker can re-seal a moved record validly, and the original
signature still disowns it.

**Independent verification** — a single standard-library-only Python
file verifies an exported audit log with zero dependency on this
codebase. What it catches:

| Attack on the log                       | Detection               |
|-----------------------------------------|--------------------------|
| Edit any field of any record            | record-hash mismatch     |
| Delete or reorder records               | per-agent chain break    |
| Forge an execution result               | anchor mismatch          |
| Runtime claims BLOCK, action ran anyway | **enforcement divergence** |

The last row closes a loop most agent-governance designs skip:
verifying that execution matched authorization. A runtime that lies
about refusing is caught from the audit file alone. Four canonical
test vectors pin these behaviors, re-verified in CI on every push.

The format, schemas (JSON Schema 2020-12, closed — unknown fields are
nonconformant by construction), test vectors, and verifier are
published as an open specification; a crosswalk to the CSA/CSAI
AARM working-group specification is maintained alongside it.

## 5. Demonstrated behavior (actual output)

One agent stream through all five levels — this is verbatim runtime
output, not an illustration:

    honest invoice payment             REQUIRE_APPROVAL  L=drift            signed=Y
    AMOUNT TAMPERED 5000 -> 49000      BLOCK             L=uaal_constraint  signed=Y
    forbidden bulk export              BLOCK             L=invariant        signed=Y
    ungranted wire transfer            REQUIRE_APPROVAL  L=authorization    signed=Y
    in-profile CRM read                ALLOW             L=baseline         signed=Y

    chains verified : True   divergent : 0   signed envelopes : 5
    independent verifier : VERDICT: PASS

    ATTACK: re-chain a signed record
    record re-seals cleanly : True
    signature still binds   : False

Three details worth attention:

1. **Precedence is observable.** The tampered payment and the wire
   transfer carry identical drift scores (0.90) yet resolve
   differently — one blocked by an enterprise constraint, one held
   for approval on authorization — each attributed to its level.
2. **Layers disagree correctly.** The honest payment passed every
   deterministic check but was escalated by the behavioral layer:
   this agent had never paid invoices before. Deterministic says
   fine; behavioral says get a human. That interplay is the design.
3. **The re-chain attack fails** despite producing an individually
   valid record: the signature pins the original hash, which pins the
   original history.

## 6. Enterprise integration

**HTTP enforcement surface.** `POST /v1/decide` — the status code is
the enforcement signal: `200` allow, `202` require-approval, `403`
block. A firewall that returns 200 for "no" gets its body ignored by
lazy integrators; the status code cannot be. Every decision is
persisted before the response returns. Companion endpoints:
`/v1/outcome` (anchored executor feedback), `/v1/blocked`,
`/v1/divergent`, `/v1/lineage/{id}`, `/v1/verify`, and
`/v1/audit/export` (verifier-ready JSONL).

**Evidence model.** Enterprise context (invoice state, canonical
targets, approval tokens) is supplied per-request by the caller; L0
evaluates only what evidence supports.

**Framework-agnostic.** An intent adapter maps
`AgentIntent(actor, verb, target, parameters)` to the internal action
contract, so the runtime sits behind whatever orchestration stack is
in use rather than replacing it.

**Deployment.** Docker/compose; SQLite (WAL) persistence with the
database strictly an index over the canonical audit format — the
exported JSONL is byte-identical to what the independent verifier
consumes, so the database can never become a second source of truth.
Current reference deployment is single-process; the multi-writer
design (chain state restored from store) is specified for the next
phase. CI runs the full suite plus the four spec vectors on every
push.

## 7. Status — precise, by design

**Shipped and tested (120 automated tests):** five-level precedence
engine; behavioral drift scoring (capability vocabulary + Markov
transition model, decomposed scores with one-sentence reasons);
grants with expiry/revocation/budget; sealed hash-chained records;
Ed25519 signing; execution anchoring; enforcement-divergence
detection; independent stdlib verifier; HTTP surface; open spec with
pinned test vectors.

**In development:** delegation chains and approval-token binding for
L2; signature-envelope persistence as a first-class record kind;
Postgres-interface storage; multi-writer deployment.

**Research track:** formal intent verification; world-state
verification in the serving path; cross-agent behavioral invariants
(topology, temporal, authority, consensus — built and unit-tested as
a library, not yet in the serving path).

**Calibration honesty:** behavioral profiles in the reference
deployment are trained on clearly-labelled synthetic traces; drift
thresholds are synthetic-calibrated. Production deployment profiles
on the customer's real execution traces. This is stated in the API's
root endpoint deliberately — a reviewer should find it self-declared.

## 8. The question for Fusion

Where does Fusion draw the line between defining what agents may do
and enforcing, pre-execution, that they do nothing else — and what
does Fusion's audit story require when an agent's action and its
authorization disagree?

If the enforcement layer described here is adjacent to that line,
everything referenced above is available for direct review:

- Runtime + demos + 120-test suite:
  https://github.com/privatevault-ai/privatevault-agent-dna
- DRP specification (schemas, test vectors, stdlib verifier, AARM
  crosswalk): https://github.com/privatevault-ai/drp-spec
- The composed demo (§5): `examples/composed_line_demo.py`; the
  independent verifier: `tools/verify_records.py`

A working session can run the composed line against scenarios of your
choosing.

---
Chandan Galani · Founder, PrivateVault AI · Mumbai
