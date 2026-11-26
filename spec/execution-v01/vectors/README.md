# execution-v01 conformance vectors

`execution-v01.json` pins what PrivateVault decides on the path from a permit
to the bytes that leave. Use it to hold another implementation to the same
decisions: a receiver in another language, the egress gateway on a DPU, or
hardware logic driven by cocotb.

| Section | What is checked | Decided in PrivateVault by |
|---|---|---|
| `authorization_cases` (EA) | A permit against the exact request, action, dispatch, bytes, TLS peer, validity window and single use | `verify_execution_authorization` |
| `presenter_cases` (PR) | The presenter a 0.2 permit names against the TLS client certificate | the receiver gate (`ReceiverGate._verify_presenter`, ADR 0022) |
| `witness_cases` (DW) | A dispatch witness against the permit and what was observed on the wire | `verify_dispatch_witness` (ADR 0008) |
| `wire_binding_cases` (WB) | The permit's byte digest against its own action | authorize (`wire_action_binding_reason`, ADR 0017) |

## Reproducing the bytes

- **Signatures.** A document is signed over the RFC 8785 (JCS) bytes of every
  field except `signature`. The value is `ed25519:` plus the base64 of the
  64-byte signature. `fixtures.ea01_signing_input_b64` is the exact signing
  input of EA-01; test your canonicalizer against it before anything else.
- **Digests** are `sha256:` plus lowercase hex. A permit's digest covers the
  RFC 8785 bytes of the whole signed document (`fixtures.ea01_authorization_digest`).
- **Wire bytes** under `pv-json-parameters/0.1` are the UTF-8 JSON of
  `action.parameters`, keys sorted by code point, no whitespace, non-ASCII
  unescaped, NaN and Infinity refused. This is not RFC 8785: key order can
  differ for non-ASCII keys and number formatting for floats. The vectors use
  ASCII keys and integers, where the two agree. Settle this before the spec
  leaves experimental.
- **Presenter identity** is `sha256:` plus the hex digest of the client
  certificate's DER SubjectPublicKeyInfo.
- **Peer identity bytes** are opaque to the verifier, which digests what it is
  given. In these vectors they are the DER SubjectPublicKeyInfo of the server's key.
- **Time.** A permit is valid from `not_before` up to, but not including,
  `expires_at` (EA-10, DW-05).

## Replaying a case

- **EA:** verify `authorization` with `trust_bundles[trust_bundle]` (null: no
  bundle) against `context`. `ledger_already_holds_id` means the durable
  single-use ledger has already claimed this permit's id.
- **PR:** present the permit from `authorization_case` with
  `client_certificate_der_b64` (null: no certificate) to a gate whose
  `gate_requires_presenter` is as given.
- **DW:** verify `witness` against EA-01's permit and the `observed` action,
  dispatch, bytes and peer.
- **WB:** check `expected_wire_bytes_digest` and `expected_wire_bytes_length`
  against `action` under `serialization`.

Match `evidence_state`, `decision_conformance` and `reason_code`. The
`failures` texts are PrivateVault's wording; another implementation should
reach the same outcome and reason code and may word its failures differently.

## Regenerating

    uv run python tools/gen_execution_vectors.py           # rewrite the file
    uv run python tools/gen_execution_vectors.py --check   # exit 1 if stale

Every case states its intended outcome in the generator, which refuses to
write the file if PrivateVault's verifiers decide otherwise.
`tests/test_execution_vectors.py` replays the committed file and fails when
it is stale. The keys are test-only: `seed_derivation` and each key's
`seed_label` say how to recreate them. Never use them anywhere else.

## What these vectors do not cover

- Both permit versions and the witness are marked experimental and may change
  before they are frozen.
- Single use is shown against one ledger. Claims racing across hosts are not
  represented; the receiver's ledger is single-host today.
- Presenter cases call the gate's check directly, not a live mTLS handshake.
