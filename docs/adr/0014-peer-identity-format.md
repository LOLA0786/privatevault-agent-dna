# 0014 — Peer identity format for the production TLS sidecar is unresolved

Status:     open
Date:       2026-08-13
Commit:     b7ad4910b433cf02540482c32db59610eeb8158c
Pinned by:  no pinning test — nothing fails if mint and observe keep using different preimages

## What forced the decision
Nothing has been decided. Two formats already exist in the tree,
and a 2036 engineer will "clean up" the ugly one.

Mint (`/v1/authorize`, demos, and most unit tests) hashes whatever
bytes the caller supplies as `expected_peer_identity_digest`. The
house convention for those bytes is the ASCII nickname
`tls-spki:payments.store.example:v3`. That is not an SPKI hash of
a certificate public key. It is a synthetic tag. Production
`TlsHttpsSidecarTransport.connect` sets `peer_identity_bytes` to
the peer certificate DER from `getpeercert(binary_form=True)`.
`verify_execution_authorization` then compares digests.

Those preimages do not match. A permit minted the way
`tools/smoke_authorize.py` and `tests/test_authorize_binding.py`
mint, then dispatched through the production TLS sidecar, fails
the post-handshake peer check and never completes EXECUTED.

The brief that asked for this record said the production path had
never completed a dispatch. That is no longer true of the in-repo
TLS tests: `tests/connector/test_sidecar_tls.py` mints over
`ssl.PEM_cert_to_DER_cert(...)` and completes EXECUTED against a
real TLS server. The remaining gap is the mint convention versus
the observer, not the sidecar's ability to send when the permit
already binds DER.

## The decision
None yet. Do not pick a format in this file.

Candidate A — full certificate DER (what the sidecar observes, what
the TLS tests already mint). Cost: every outstanding permit dies on
certificate rotation, including a same-key reissue. Binds SAN,
expiry, and extensions, not only the key.

Candidate B — SPKI hash of the authenticated public key (what the
`tls-spki:` name pretends to be). Cost: survives rotation of the
certificate wrapper; binds less; does not match today's mint bytes,
which are nicknames, not SPKI. The sidecar would have to derive
SPKI from DER, and mint would have to hash the same derivation.

## What this costs us
Until one format is used on both sides of a live mint→TLS dispatch,
the production authorize API and the production sidecar are not a
completed path. Recording transports hide this because they echo
the synthetic tag they were constructed with.

## What would make us revisit
Run mint through `/v1/authorize` (or composition's sidecar) against
a real TLS server without a test double supplying the peer, then
supersede this ADR with the format that actually verified. Do not
supersede from a paper choice. A helper that hashes DER in tests
while the API still accepts `tls-spki:...` is not a resolution.
