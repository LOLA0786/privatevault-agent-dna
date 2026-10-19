# 0026: The evidence a permit cites is the server's, not the caller's

Status:     accepted
Date:       2026-10-19
Pinned by:  tests/test_permit_evidence.py::test_secure_profile_refuses_the_reviews_probe;
            tests/test_permit_evidence.py::test_server_mode_refuses_caller_evidence;
            tests/test_permit_evidence.py::test_server_mode_refuses_after_a_configuration_change;
            tests/test_permit_evidence.py::test_decide_seals_the_permit_evidence;
            tests/test_permit_evidence.py::test_secure_profile_refuses_caller_mode_at_startup

## What forced the decision
An external review (19 October 2026, finding 3) sent `/v1/authorize`
arbitrary values for four permit fields: `policy_bundle_digest`,
`authority_receipt_digest`, `state_snapshot_digest` and
`obligations_digest`. The server signed them unchanged. Nothing resolved
them to stored evidence, so the signature said only that a caller had
named those digests, not that any policy or state had been checked.

## The decision
The server fixes all four when it decides
(`agent_dna/permit_evidence.py`) and seals them into the decision record,
inside the control-posture evidence item, which a caller cannot write:

- `policy_bundle_digest`: the decision configuration this server loaded at
  start-up: the policy file's bytes (or the OPA endpoint, policy path and
  bundle bytes), the grants file's bytes and the operations registry
  digest. `/v1/runtime` reports it.
- `authority_receipt_digest`: the grant the engine decided under, as
  configured (id, agent, capability, granted_by, expiry, budget; not spend
  or revocation state), or the all-zero digest without a grant.
- `state_snapshot_digest` and `obligations_digest`: the all-zero digest.
  The API evaluates no enterprise state snapshot and attaches no
  obligations, so its signature does not claim either.

`PV_PERMIT_EVIDENCE` chooses what `/v1/authorize` signs:

- `server` (the default under `PV_SECURE_PROFILE`): the sealed values. A
  caller may omit the four fields or repeat the sealed values; a different
  value is refused (`AUTHORIZE_EVIDENCE_MISMATCH`). If the server's
  decision configuration differs from the one sealed in the record (policy,
  grants or operations file changed between decide and mint, or a mint on
  an instance configured differently) the mint is refused
  (`AUTHORIZE_POLICY_CHANGED`). A record with no sealed evidence (decided
  before this change) is refused (`AUTHORIZE_EVIDENCE_UNKNOWN`).
- `caller` (the default without the secure profile; refused at start-up
  with it): a value the caller sends is signed as given, as before; an
  omitted one is the sealed value. The response lists the fields that are
  the caller's assertions.

The mint response's `evidence` object names the mode, the four values
signed and `caller_asserted`. The permit format is unchanged: no new field,
no Rust or verifier change.

## What this costs us
- Integrations that sent placeholder digests must stop sending them under
  the secure profile. Shipped clients (the agent gate, the partner pack)
  now omit them and read the signed values from the permit.
- Editing the policy, grants or operations file and restarting refuses
  mints for decisions made before the restart, for the length of the mint
  window. During a rolling deploy, a decision made on an old instance does
  not mint on a new one. Decide again.
- For an OPA endpoint the digest names where the policy lives, not what the
  remote policy said. A bundle file is digested by content.
- The digest is of the files as read at start-up, a moment after the
  composition root reads them for the engine; a file replaced in between
  would be digested in its new form.
- Off the secure profile the four values are still the caller's if the
  caller sends them, and the response says so. **We do not claim** that a
  permit minted in caller mode proves policy or state was checked.

## What would make us revisit
An enterprise state snapshot or obligations the API actually evaluates
(then their digests replace the all-zero value), a signed policy bundle
served separately from the API, or receivers that check these references
themselves (permit spec 0.3).
