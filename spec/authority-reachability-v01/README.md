# Authority Reachability v0.1-experimental

Authority Reachability is deterministic blast-radius analysis over a fixed,
typed graph snapshot. It does not use probability, behavioral training data,
or inferred intent.

The implementation is isolated in
`experimental/authority_reachability_v01/`. It is not part of the installable
runtime and is not yet a production claim.

## Security question

Given a source agent, fixed analysis time, concrete context, authority
relationships and imported company topology:

1. Which protected irreversible actions are reachable?
2. What is the shortest deterministic witness path?
3. Which edges are declared, discovered, observed, unverifiable or invalid?
4. Does a path violate an explicit protected-sink rule?
5. What new reachability would a proposed graph change create?

The analyzer never claims that a path was “unintended.” It reports violations
of declared invariants such as direct-grant requirements, allowed issuers and
maximum delegation depth.

## Trust boundary

Company and knowledge-graph adapters cannot emit `VERIFIED` evidence.

They may emit:

- `DECLARED`
- `DISCOVERED`
- `OBSERVED`
- `UNVERIFIABLE`
- `INVALID`

Only a cryptographic authority adapter that validates signatures, trusted
roots, key continuity, delegation attenuation and validity windows may emit
`VERIFIED`.

The v0.1 synthetic demonstration uses `DECLARED` authority relationships and
one `DISCOVERED` identity relationship. Its reachability result is
deterministic, but it is not represented as cryptographically verified
authority.

The output report can be hashed and Ed25519-signed. The current signing and
verification functions share the experimental implementation and are not an
independently implemented verifier.

## Canonical node states

- `PRINCIPAL`
- `AGENT`
- `IDENTITY`
- `GRANT`
- `CAPABILITY`
- `ACTION`
- `TOOL`
- `RESOURCE`
- `SERVICE`
- `IRREVERSIBLE_SINK`

## Canonical directed edges

- `ISSUED`
- `HOLDS_GRANT`
- `DELEGATED_TO`
- `GRANTS`
- `AUTHORIZES`
- `CAN_ASSUME`
- `CAN_INVOKE`
- `EXPOSES`
- `ENABLES`
- `READS`
- `WRITES`
- `SCOPED_TO`
- `REQUIRES_APPROVAL`

Every edge explicitly declares whether it is traversable. Metadata edges can
remain in the graph without accidentally creating authority paths.

## Evidence classes

- `VERIFIED`: reserved for cryptographically checked authority evidence.
- `DECLARED`: supplied by approved customer configuration.
- `DISCOVERED`: read from a platform, identity system or knowledge graph.
- `OBSERVED`: derived from execution records.
- `UNVERIFIABLE`: topology might exist but evidence is incomplete.
- `INVALID`: integrity or signature validation failed; never traversed.

Imported company topology is never silently upgraded to verified authority.

## Reachability states

- `UNREACHABLE`: no active directed path exists.
- `REACHABLE`: a concrete path exists and violates no sink invariant.
- `PROHIBITED_REACHABLE`: a concrete path violates a declared sink invariant.
- `CONDITIONAL`: a possible path depends on unresolved context or
  unverifiable evidence.

Conditions that evaluate false remove an edge. Missing facts make a path
conditional, not unreachable. This prevents unsupported conditions from
creating false assurances.

## Determinism

The analyzer sorts adjacency lists and protected sinks, uses breadth-first
search, and hashes canonical float-free I-JSON.

The same graph, source, context and analysis time produce the same report and
analysis identifier.

Shortest-path reachability is `O(|V| + |E|)` for each protected sink.

## Files

- `authority-graph.schema.json`: canonical graph snapshot contract.
- `reachability-report.schema.json`: deterministic report contract.
- `vectors/company-graph-before.json`: raw synthetic company export.
- `vectors/company-graph-after.json`: export with a proposed identity binding.
- `vectors/adapter-mapping.json`: explicit company-to-PrivateVault mappings.
- `vectors/analysis-context.json`: fixed evaluation context.
- `vectors/expected-analysis.json`: expected results, separate from input.

## Commands

Generate the vectors:

```text
python tools/generate_authority_reachability_vectors.py
Run the demonstration:

python examples/authority_blast_radius_demo.py

Compare before and after:

python tools/pv_authority_reachability.py simulate \
  spec/authority-reachability-v01/vectors/company-graph-before.json \
  spec/authority-reachability-v01/vectors/company-graph-after.json \
  spec/authority-reachability-v01/vectors/adapter-mapping.json \
  --source agent:refund \
  --context spec/authority-reachability-v01/vectors/analysis-context.json

A prohibited proposed change exits with status 1.
