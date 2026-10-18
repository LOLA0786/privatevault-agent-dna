# 0022: The receiver gate authenticates who presents a permit (mTLS, SPKI pin)

Status:     accepted
Date:       2026-10-18
Pinned by:  tests/receiver/test_presenter_mtls.py::test_only_the_bound_presenter_gets_through;
            tests/receiver/test_presenter.py::test_gate_refuses_another_key_without_burning_the_permit;
            tests/receiver/test_presenter.py::test_rebinding_the_presenter_breaks_the_signature;
            tests/receiver/test_presenter.py::test_identity_matches_openssl_and_cryptography;
            tests/test_authorize_presenter.py::test_another_agents_or_unknown_key_is_refused

## What forced the decision
A permit binds the agent, the action and the exact bytes (ADR 0019). The
gate did not know who presented it: a process that obtained agent A's
permit and A's bytes could present them once, before A did, and the gate
would admit them because they were exactly what A was authorised to send
(docs/ROADMAP.md, "presenter identity").

## The decision
**Identity.** A presenter is a TLS client key. Its identity is `sha256:` +
hex SHA-256 of the certificate's DER `SubjectPublicKeyInfo` (RFC 7469
`pin-sha256`). It survives re-issuing the certificate for the same key and
changes with the key. It is computed without parsing anything but the DER
path to the SPKI (`agent_dna/presenter_identity.py`), cross-checked against
openssl and `cryptography` in tests. This decides the presenter direction
only; ADR 0014 (the receiver's identity, `expected_peer_identity_digest`)
stays open.

**Binding.** Permit spec `pv-execution-authorization/0.2-experimental` adds
one signed field, `expected_presenter_identity_digest`
(`spec/execution-v01/execution-authorization-v02.schema.json`). Spec 0.1
permits remain valid.

**Who chooses the key.** The operator pins presenters per agent in a
presenter bundle (`PV_PRESENTER_BUNDLE`, `pv-presenter-bundle/0.1`; several
digests per agent allow rotation). With a bundle configured, `/v1/authorize`
requires `presenter_identity_digest`, refuses one not pinned for the
authenticated agent (`AUTHORIZE_PRESENTER_NOT_PINNED`), and mints 0.2.
Without a bundle a requested presenter is refused
(`AUTHORIZE_PRESENTER_UNCONFIGURED`), never silently dropped.

**Enforcement.** The gate serves mTLS (`agent_dna/receiver/tls.py`: client
certificate required from the operator's client CA; a uvicorn protocol puts
the verified certificate into the request scope, and the standard ASGI
`tls` extension is also read). For a 0.2 permit the client key must equal
the bound presenter, checked right after the permit signature and before
the ledger: a wrong or missing presenter is refused with signed evidence
and does not consume the permit. `require_presenter`
(`PV_RECEIVER_REQUIRE_PRESENTER=1`) also refuses 0.1 permits.

## What this costs us
- Every agent sidecar needs a client certificate and key, and the operator
  maintains the presenter bundle and the client CA.
- Removing a key from the bundle stops new mints for it at once; permits
  already minted for it stay valid until they expire (one minute by
  default). The gate does not check CRLs or OCSP: trust is the client CA
  plus the pinned key.
- The presenter is an mTLS identity of a process or host, not of a person.
  Separation holds only for covered flows where enforcement is enabled and
  verified.

## What would make us revisit
A deployment whose client identity comes from somewhere else (a service
mesh's SPIFFE ID in a forwarded header, hardware attestation), or a need to
bind more than the key (the full certificate, or a SPIFFE URI SAN).
