# 0009 — A key may not both mint permits and witness them

Status:     accepted
Date:       2026-07-31
Commit:     8e659f2892a36ef4fddcaa3a88432557882b2abd
Pinned by:  tests/test_dispatch_v01.py::test_same_public_key_is_not_independent

## What forced the decision
One Ed25519 seed for mint, witness, and closure is operationally
easy: one env var, one rotation, one HSM slot. It is tempting in
every greenfield deploy and every "just get the demo signing."

If that key is compromised, the attacker mints a permit, witnesses
a send that never happened, and signs closure. The chain is
internally consistent and entirely fictional. Independence is the
only property that makes the witness a second opinion rather than
a second signature from the same liar.

## The decision
Execution-authorization signer, dispatch-witness signer, and
closure signer must be distinct keys and distinct principals.
Same `key_id`, same public key, or same principal is
`WITNESS_NOT_INDEPENDENT` / `CLOSURE_NOT_INDEPENDENT_OF_AUTHORIZATION`.
Usage flags are not enough: a key that merely lacks
`dispatch_witness_signer` is `WITNESS_KEY_USAGE_INVALID`; a key
that has the usage but is the mint key still fails independence.
The secure profile requires both usages to be present in the
pinned bundle and a witness key file that matches the witness
principal, not the mint principal.

## What this costs us
Every deployment holds at least two secrets. Rotation is two
ceremonies. Tests that generate one `SigningKey` and reuse it
will fail closed, which has surprised us more than once.

## What would make us revisit
HSM or TEE attestation that can prove two roles were exercised
in isolated boundaries even if the operator thought they were
one key — with a test that a single seed still cannot verify
both signatures. Collapsing keys to cut Secret Manager cost is
not a trigger.
