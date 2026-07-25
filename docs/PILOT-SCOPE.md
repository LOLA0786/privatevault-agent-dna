# PrivateVault Decision Security Runtime — Pilot Scope

Template for a single-enterprise pilot · drp/0.1 · July 2026

## 1. Objective

Deploy the runtime as a pre-execution decision layer in front of one
agent workflow of the customer's choosing, and demonstrate over a
4–6 week window that: (a) unauthorized or anomalous actions are
refused before execution, (b) every decision — including refusals —
is recorded in a tamper-evident, independently verifiable audit
trail, and (c) the behavioral layer, once profiled on the customer's
real execution traces, produces actionable early warnings with an
agreed false-positive ceiling.

## 2. What the customer provides

- **One agent workflow** with an enumerable capability surface
  (e.g. a payments, reconciliation, or claims agent) and the ability
  to route its tool calls through `POST /v1/decide`.
- **Execution traces** from that workflow (historical or live
  shadow-mode) for behavioral profiling. Format: action stream of
  (agent_id, capability, timestamp, arguments). Raw arguments never
  leave the customer environment — the runtime stores digests only.
- **Evidence sources for L0**: whichever enterprise state the pilot
  invariants check (e.g. invoice records, canonical target
  registries, approval-token issuance). Supplied per-request by the
  caller; the evidence-supply contract is agreed in week 1.
- **A named risk/security reviewer** for the audit-verification
  exercise in week 4.

## 3. Deployment model

Single container (Docker/compose) inside the customer's environment —
no data leaves it. SQLite/WAL persistence on a customer volume; the
canonical audit artifact is the exported JSONL, verifiable with a
independent Python verifier the customer keeps; chain mode uses only the standard library. API-key
authentication (hashed at rest); Ed25519 signing keyed from the
customer's secret store. Single-process reference deployment;
restart-safe (chain state restores from store — test-covered).

## 4. Pilot phases

**Week 1 — Shadow.** Runtime observes the workflow without enforcing
(all decisions recorded, none blocking). Behavioral profile trains on
the customer's traces, replacing the synthetic calibration. Evidence
contract for L0 finalized.

**Weeks 2–3 — Enforce on a bounded capability set.** L0 constraints
and L1 invariants agreed with the risk owner go live; L2 grants
issued with expiry/budget; L3 drift thresholds set from the week-1
profile. REQUIRE_APPROVAL routes to the customer's existing human
queue.

**Week 4 — Adversarial + audit exercise.** Jointly scripted attack
scenarios (amount tampering, target redirection, revoked-grant use,
out-of-profile capability). Customer's reviewer independently
verifies the exported audit log — including a deliberate tamper test
on a copy — using only `verify_records.py`.

**Weeks 5–6 — Report.** Refusal accuracy, false-positive rate against
the agreed ceiling, divergence count (target: zero), audit
verification results, and a production-hardening plan.

## 5. Success criteria (agreed before start, measured at end)

1. 100% of scripted unauthorized actions refused pre-execution, each
   attributed to its precedence level in the record.
2. Zero enforcement divergences (no BLOCK that executed).
3. Audit export passes independent verification by the customer's
   reviewer, and the tamper test fails verification as specified.
4. L3 false-positive rate at or under the agreed ceiling after
   profiling on real traces (ceiling set in week 1 — not promised in
   advance of seeing the data).
5. p95 decision latency under an agreed budget, measured in the
   customer environment (no latency figures are claimed in advance).

## 6. Known limitations, stated up front

- Single-process deployment; multi-writer is designed, not shipped.
- Signature envelopes are retrievable for the current process
  lifetime; envelope persistence as a first-class record kind is
  roadmap.
- Delegation chains, mid-session grant rescoping, and approval-token
  binding are roadmap; L2 in the pilot is grants with
  expiry/revocation/budget.
- Behavioral accuracy figures prior to week-1 profiling are
  synthetic-calibrated and are not pilot claims.

## 7. Commercial frame

Paid pilot; fee and production-license terms discussed separately.
The DRP wire format, schemas, test vectors, and verifier are open
(Apache-2.0 / CC-BY-4.0) — the customer's audit artifacts are never
locked to the vendor. The runtime is commercial.

---
PrivateVault AI (Pentaprime Solutions) · Mumbai · privatevault.ai
