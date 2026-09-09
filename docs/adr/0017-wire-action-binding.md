# 0017 — Trusted action↔wire binding at authorize

Status:     accepted
Date:       2026-09-07
Pinned by:  tests/test_wire_action_binding.py

## What forced the decision
Decide seals an execution action and a dispatch-context digest. Authorize
still accepted independent caller-supplied `expected_wire_bytes_digest`
values. A first mint could therefore present action parameters
`quantity_tonnes=40` while claiming wire bytes for `quantity_tonnes=400`,
and verification would succeed because both digests were simply signed.

Signing two caller-supplied hashes does not prove they represent the
same semantic action. The existing second-mint binding-conflict tests
did not cover first-mint inconsistency.

## The decision
1. Introduce named wire serialization contract `pv-json-parameters/0.1`
   (`agent_dna/wire_serialization_v01.py`).
2. Widen sealed dispatch context to `pv-dispatch-context/0.2` with
   required field `serialization`. Legacy `pv-dispatch-context/0.1`
   remains readable but is non-authorizing for mint.
3. Execution-authorization and observed-dispatch closed schemas require
   the same `serialization` field.
4. `/v1/decide` refuses when optional wire digests are present but do
   not equal the named serialization of `execution_action.parameters`.
5. `bind_authorize_to_sealed_allow` re-derives wire bytes from the sealed
   action under the named serialization and refuses
   `AUTHORIZE_WIRE_ACTION_MISMATCH` (or serialization required/unknown)
   before mint claim. Direct `/v1/authorize` callers cannot bypass this.

## Consequences
- Valid consistent action/wire pairs still mint.
- First-mint body swap and decide-time inconsistent pairs refuse.
- Second-mint tampered wire now fails as wire-action mismatch rather
  than permit-binding conflict (stronger, earlier refuse).
- Adapters must prepare wire bodies with the named serializer
  (`sort_keys=True` JSON for `pv-json-parameters/0.1`).

## Compatibility
- Closed schemas widen with a required field — callers/tests must send
  `serialization`.
- No validation disablement; unknown serialization names refuse.

## Integration scope
- Generic connector and gateway decisions use `pv-audit-only/0.1` in
  their sealed context. The middleware sets it independently of caller
  context. It is not a request-body serializer and cannot mint a permit.
  Existing policy gates and audit records remain functional.
- Mintable JSON-body requests use `pv-json-parameters/0.1`. A raw MCP
  envelope, framing bytes, or the HTTPS gateway's method/URL/body frame
  is not this format. Supporting their signed permits requires distinct
  transport contracts; this change does not claim that integration.
- `legacy_dispatch_context_digest` reproduces the original five-field
  digest for historical audit only. It does not insert a serializer,
  rewrite signed artifacts, or authorize a new request. Normal context
  validation still requires six fields. This is not a migration of old
  execution permits or witness artifacts into executable authority.
- Runtime permit and witness validators reject unknown and audit-only
  serializer names, matching the existing JSON schemas.
- Campfire examples, Postman payloads, README and smoke tests derive
  wire hashes and lengths from their actual action parameters. They no
  longer use arbitrary zero digests for supposedly valid request bodies.

Regressions: `tests/test_wire_action_binding.py`, connector/gateway/shadow
suites, Campfire pack tests, and executive/refund acceptance demos.
