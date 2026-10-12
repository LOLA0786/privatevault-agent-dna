# Security policy

Do not report exploitable vulnerabilities in a public issue. Email
`security@privatevault.ai` with reproduction steps, affected versions, and the
impact you observed. We aim to acknowledge reports within 72 hours.

The complete threat model, trust assumptions, supported controls, and residual
risks are maintained in [`docs/SECURITY.md`](docs/SECURITY.md). Product claims
and explicit non-claims are maintained in
[`docs/WHAT-WE-DO-NOT-CLAIM.md`](docs/WHAT-WE-DO-NOT-CLAIM.md).

## Fixed issues

Found by internal audit unless stated otherwise. Each entry names the test
that now pins the behaviour.

- 2026-10-12. `ExactByteHttpDispatcher` evaluated a permit's
  `not_before`/`expires_at` window against the caller-supplied
  `ExactByteContext.at_time` rather than the sidecar's own clock. A caller
  that echoed the mint time could dispatch an expired permit at any later
  time. The receiver gate and the mint replay path were not affected. The
  dispatcher now judges the window by its own clock, which the caller cannot
  set. Pinned by
  `tests/connector/test_exact_byte_http.py::test_expired_permit_refused_even_when_caller_claims_earlier_time`.
