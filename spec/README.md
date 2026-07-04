# DRP Decision Records — Format & Independent Verification

Open wire format for tamper-evident AI-agent decision audit trails,
with test vectors and a standard-library-only verifier.

## What this is

Every pre-execution authorization decision an agent runtime makes is
serialized as a sealed, hash-chained JSON record. Executor results are
appended as separate events cryptographically anchored to the decision
they report on. The resulting JSONL file can be verified by anyone,
with nothing but Python 3 and `verify_records.py` — no dependency on
the runtime that produced it.

## Record kinds

**decision** — one per authorization decision.
Per-agent hash chain: `prev_hash` = previous decision's `record_hash`
(genesis: 64 zeros). `record_hash` = SHA-256 of the canonical JSON
payload (all fields except `record_hash`, sorted keys, compact
separators). Raw action arguments are never stored — only
`arguments_digest`.

**execution** — at most one per decision.
`prev_hash` = the referenced decision's `record_hash` (anchor binding).
`status` ∈ `ok | error | refused`.

Records carry an `edges` list. Produced today: `follows`
(decision → parent decision), `resulted_in` (execution → decision).
Edge types are added only when a component produces them.

## What verification proves

| Attack on the log            | Detected by                  |
|------------------------------|------------------------------|
| Edit any field of any record | record_hash mismatch         |
| Delete a record              | per-agent chain break        |
| Reorder records              | chain break                  |
| Forge an execution result    | anchor mismatch              |
| Runtime claims BLOCK, action executed anyway | ENFORCEMENT DIVERGENCE |

The last row is the one that matters: a runtime that lies about
refusing is caught from the audit file alone.

## Test vectors

`test-vectors/` contains four canonical files and their required
verdicts:

| Vector                 | Verdict | Failure class          |
|------------------------|---------|------------------------|
| clean.jsonl            | PASS    | —                      |
| tampered_field.jsonl   | FAIL    | record_hash mismatch   |
| deleted_record.jsonl   | FAIL    | chain break            |
| divergent.jsonl        | FAIL    | enforcement divergence |

Verify any of them:

    python3 ../tools/verify_records.py test-vectors/clean.jsonl

A conformant implementation of this format MUST produce files that
pass, and MUST NOT produce files whose tampering evades these checks.

## Scope honesty

This format covers decision lineage, execution anchoring, and tamper
evidence. It does not yet cover: cryptographic signing (Ed25519
signing belongs to the enforcement runtime layer above this format),
approval workflows, policy versioning, or delegation (branching
lineage). Fields for these are schema-reserved and null until a
producing component exists.
