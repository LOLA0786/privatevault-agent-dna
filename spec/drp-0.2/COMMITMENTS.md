# DRP 0.2 — Algorithm-agile commitments

Status: draft. Not implemented. No conformant implementation exists.

## Problem

DRP 0.1 commits to record contents under SHA-256 only. Records are
retained for evidentiary purposes over horizons (7–10 years in BFSI)
that exceed the period for which a single hash function can be assumed
sound.

RFC 4998 addresses this by hash-tree renewal: re-access every covered
data object and rehash it under a stronger algorithm. DRP cannot do
this. `arguments_digest` retains a digest, not the arguments
(`test_raw_arguments_never_stored`); `sha256_bytes_digest` retains a
digest of the wire bytes, not the bytes. Where only a digest was kept,
the original is unavailable by construction and rehashing is impossible.

This is a consequence of data minimization, which is a deliberate
property, not a defect. DRP 0.2 therefore commits contemporaneously
under a second hash function rather than renewing later.

## Normative changes

    protocol_version  "drp/0.2"

    payload()         unchanged in shape from 0.1 apart from
                      protocol_version. Field set, ordering rule,
                      and canonicalization are identical.

    canonical(p)      unchanged: JSON, sorted keys, separators
                      (",", ":"), no non-finite floats, no type
                      coercion.

    record_hash       = SHA-256(canonical(payload))
                      Unchanged. Remains the chain link: prev_hash of
                      the next record for the same agent_id.

    commitments       = {
                          "sha-256":  <hex>,
                          "sha3-256": <hex>
                        }
                      Sibling of record_hash. NOT a member of payload.
                      Both digests are computed over the identical
                      octet string canonical(payload).

    signed digest     = SHA3-256(canonical(commitments))
                      In 0.1 the signature was over record_hash.

### Why the signature moves

A commitment outside the signed surface is not load-bearing. An
adversary holding a SHA-256 collision substitutes the payload and
rewrites an unsigned `commitments` block to match; every check still
passes. Signing over the commitments block means substituting a
SHA-2-colliding payload changes the SHA3-256 entry, changes the signed
digest, and breaks the signature.

The alternative — placing `commitments` inside `payload` — is circular:
the digests would cover a structure containing themselves. Resolving it
requires a second canonical form (payload-minus-commitments) and
therefore a second Python/Rust parity surface. DRP 0.2 does not do this.

### Redundancy is intentional

`commitments["sha-256"]` equals `record_hash` by construction.
Verifiers MUST check this equality. The redundancy lets a verifier treat
`commitments` as an algorithm-agile map and select an entry by policy,
rather than special-casing `record_hash`. A verifier that no longer
accepts SHA-2 can ignore `record_hash` as a security claim, verify
`sha3-256`, and treat `prev_hash` as an opaque chain identifier.

## Verifier requirements

A DRP 0.2 verifier MUST:

1. Reject a record whose `commitments` lacks any algorithm the
   verifier's policy requires.
2. Recompute every entry in `commitments` over canonical(payload) and
   reject on any mismatch. It MUST NOT verify only the entry it
   prefers: an unchecked entry is an unchecked claim.
3. Reject a record where `commitments["sha-256"] != record_hash`.
4. Verify the signature over SHA3-256(canonical(commitments)).
5. Verify chain continuity via `prev_hash` == predecessor
   `record_hash`, unchanged from 0.1.

A verifier MUST reject a record whose `protocol_version` it does not
implement. It MUST NOT infer 0.2 semantics from the presence of a
`commitments` field, nor 0.1 semantics from its absence.

## Coexistence

0.1 and 0.2 records may appear in one file and one agent chain. The
chain link is algorithm-identical across the boundary (`record_hash`
remains SHA-256), so continuity holds without a migration record.

`spec/schemas/decision_record.schema.json` pins
`protocol_version: {"const": "drp/0.1"}` under
`additionalProperties: false` and so cannot describe both. DRP 0.2
adds a parallel schema file; verifiers dispatch on `protocol_version`.

Existing vectors under `spec/test-vectors/` are pinned by
`test_vector_immutability` and MUST NOT be regenerated. DRP 0.2
vectors live in a new directory.

## Algorithm selection

SHA3-256 is chosen over SHA-384 because it is a different construction
(sponge, not Merkle–Damgård). A structural weakness in the SHA-2 family
would affect SHA-384 and SHA-256 together; the second commitment exists
precisely to survive that case, so intra-family agility does not serve
the purpose. CNSA 2.0 names SHA-384, selecting within one family on
performance grounds. Implementations requiring CNSA alignment MAY add a
`"sha-384"` entry; the format admits any number of algorithms.

## What this does not do

Dual commitment addresses hash weakening only.

It does not address signature weakening. If Ed25519 is broken, an
adversary can forge records and their signatures regardless of how many
hash algorithms each record commits under. That requires renewal with an
external time anchor, which DRP does not specify. Operator-signed
renewal is self-attestation and provides no protection against the
operator.

It does not make discarded evidence recoverable. A payload not retained
remains unavailable; DRP 0.2 preserves the ability to verify the
*commitment* under a future hash function, not the ability to inspect
what was committed to.

It does not extend to records written under 0.1. Those remain
hash-terminal. Every record written before this change is permanently
committed under SHA-256 alone.
