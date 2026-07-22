# drp-observer/1 — Effect / Decision Reconciliation

Status: draft. Companion to the DRP decision-record spec (drp/0.1).
Reference reconciler: `tools/reconcile_effects.py` (standard library
only). Canonical vectors: `observer/vectors/` (SHA256-pinned in
`SHA256SUMS`).

## The boundary this spec sits on

Complete mediation is the property that every real external effect an
agent produces was authorized by a prior decision. It decomposes into
two statements that must be kept separate, because one is provable and
one is not:

    Effect => Observed                            TCB ASSUMPTION
    ObservedEffect => exists! PriorValidAllow      THEOREM (this spec)

`Effect => Observed` is a physical coverage property of the customer's
containment layer — a network namespace, an eBPF egress hook, a syscall
filter, a target-native receipt. No log and no signature can prove that
an effect which was never captured did not occur. This spec does not
attempt to prove it, and no honest system claims to.

`ObservedEffect => exists! PriorValidAllow` is a theorem over captured
effects: every effect an observer DID record must reconcile to exactly
one prior, valid, matching, fresh ALLOW decision. This spec defines the
records and the verifier that proves it.

The value of the spec is that it makes the *gap* between assumption and
theorem auditable. Omission is not made impossible — it is made
detectable, through coverage epochs and independent observers.

## Ownership (trust boundary, minimized not eliminated)

- The **decision log** is owned by the runtime/customer deployment.
- **Effect capture and signing** are owned by customer-controlled
  containment. Effects are signed by the observer.
- **Keys** live outside both the agent and the runtime — ideally a
  customer HSM/KMS. An observer whose key the agent can reach is not
  independent.
- **Reconciliation** (this spec) detects disagreement between the
  independent decision and effect streams. It asserts neither stream is
  authoritative; a reconciliation failure is itself the finding.

## Records

### effect

    { "kind": "effect",
      "observer_id": "...",
      "seq": 42,
      "decision_ref": "d-..."|null,
      "effect_type": "...",
      "target": "...",
      "timestamp": 0.0,
      "epoch_id": "...",
      "observer_sig": "...",
      "record_hash": "..." }

### coverage_epoch

    { "kind": "coverage_epoch",
      "observer_id": "...",
      "epoch_id": "...",
      "seq_start": 1, "seq_end": 100,
      "window_start": 0.0, "window_end": 0.0,
      "observer_sig": "...",
      "record_hash": "..." }

A coverage epoch is a signed positive assertion: "I, this observer,
captured every effect with sequence in [seq_start, seq_end]." A missing
sequence number inside an asserted epoch is an `OBSERVER_GAP` — a window
where an omitted effect could hide, surfaced rather than ignored. The
absence of any epoch covering an effect is itself a gap: coverage that
is not claimed cannot be relied upon.

## Verdicts

| Verdict | Meaning |
|---|---|
| `UNAUTHORIZED_EFFECT` | observed effect with no matching ALLOW, or matching a non-ALLOW decision, or failing binding/freshness |
| `ORPHAN_EFFECT` | observed effect carrying no `decision_ref` |
| `OBSERVER_GAP` | sequence gap inside an epoch, or effect outside every epoch |
| `BLOCK_EXECUTED` | a decision was BLOCK yet an effect was observed for it |
| `RECORD_TAMPERED` | an effect/epoch `record_hash` does not match its content |
| `UNSIGNED_OBSERVATION` | an effect/epoch carries no `observer_sig` |

## Binding and freshness

- **Binds(d, x)**: the effect's target/type matches the decision's
  capability or argument digest.
- **Fresh(d)**: the effect occurs at or after the decision, within a
  bounded authorization window (reference default 300s). An ALLOW does
  not authorize an effect indefinitely.

## Multiple independent observers

N observers produce N independent effect streams, all reconciled
against the one decision log. If observer A stays silent about an effect
that observer B captured, B's stream still raises `UNAUTHORIZED_EFFECT`.
A single observer can be silenced; independent observers must be
silenced in concert, and their coverage epochs forged in concert, to
hide an effect — and any inconsistency between them is a finding.

## What this spec does NOT prove

It does not prove `Effect => Observed`. External checkpoints,
target-native receipts and multiple observers make tampering harder and
disagreement visible, but they do not mathematically prove that an
unobserved effect never occurred. Assurance remains conditional on the
integrity and coverage of the customer's containment layer, which is
part of the customer's trusted computing base. This is stated plainly
because it survives an auditor's first question.

## Reference verifier

    python3 tools/reconcile_effects.py <decision_log.jsonl> <effect_log.jsonl> [...]

Standard library only, no dependency on any producing runtime. Exit
code 0 iff no findings. Canonical vectors demonstrating each verdict
are in `observer/vectors/`, pinned in `SHA256SUMS`.
