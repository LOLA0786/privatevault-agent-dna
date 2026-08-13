# 0007 — The execution trust bundle is deployment-pinned, not caller-supplied

Status:     accepted
Date:       2026-08-13
Commit:     09dde9a71e2a7bfa45ec4ef15a4d64e73313a61d
Pinned by:  tests/connector/test_exact_byte_http.py::test_attacker_controlled_trust_bundle_never_sends

## What forced the decision
Passing `trust_bundle=` (or a send callback, or a peer identity)
into `dispatch()` looks like good API design: tests inject fakes,
multi-tenant callers bring their own roots, and the sidecar stays
"pure." It is also how an attacker selects the keys that will
bless their permit. A mathematically valid signature under a
caller-chosen root is not a deployment trust decision.

The changelog for the first exact-byte ship claimed the secure
profile required the bundle before that was fully true. The
correction was to load `PV_EXECUTION_TRUST_BUNDLE_FILE` at
construction and refuse caller substitution at dispatch time.

## The decision
Production composition loads the execution trust bundle once from
the environment. `ExactByteHttpDispatcher.dispatch` rejects
`trust_bundle`, `peer_identity_bytes`, and `send` if supplied.
Callers cannot select a trust root, a TLS peer, or a transport at
the moment of send. An arbitrary `SendFn` is test-only and does
not prove bytes on the wire.

## What this costs us
Tests must go through recording/TLS doubles rather than stuffing
roots per call. Multi-tenant roots are an operator restart (new
bundle file), not a request field. The bundle is still unsigned
in authority v0.1: an operator who can write the file can make a
forged historical permit verify.

## What would make us revisit
Signed, versioned bundles (authority v0.2) with rotation that does
not require process restart, plus a test that a request-scoped
bundle is still refused. Adding `trust_bundle` back as a convenience
for notebooks is not a trigger.
