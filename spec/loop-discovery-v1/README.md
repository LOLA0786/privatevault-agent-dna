# PrivateVault Loop Discovery v1

This directory defines the wire contract for deterministic, cross-agent loop
discovery. The runtime implementation is
`agent_dna.security.loop_discovery`; the schemas are the interoperability
surface.

An event records one immutable, directed security edge and binds it to the
digest of the corresponding `ActionIntent` or grant. `authorization_id` is a
single-use authorization identifier issued by the control plane. Model output,
framework callbacks, and unsigned labels are not authorization evidence.

The analyzer separates four conditions:

1. `DELEGATES` and `APPROVES` cycles are authority contradictions and block.
2. Causal parent cycles, excessive depth, and authorization reuse block.
3. Repeated canonical actions are reviewed on the second occurrence and block
   on the third occurrence by default.
4. A bidirectional `INVOKES` graph is reviewed. It is not mislabeled as
   circular authority; stronger causal or replay evidence is required to block.

The report is deterministic for the same set of input events. `input_digest`
binds the normalized input and `report_id` binds the decision and findings.
These digests provide integrity identifiers; they are not signatures.

## Compatibility

Consumers must reject unknown fields and unsupported enum values. A future
semantic change requires a new `spec` value. Producers must use RFC 3339 UTC
timestamps and lowercase SHA-256 digests.
