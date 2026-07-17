# Network Effects — Behavioral Profile Marketplace

## Concept
Every agent decision produces behavioral evidence. When aggregated
across organizations (without exposing agent identity or raw data),
these patterns become a collective defense layer — stronger for
every participant.

## Architecture
`agent_dna/marketplace/` provides three modules:

- `analytics.py` — Aggregate statistics (verdict rates, drift bins,
  invariant hits) with zero identity exposure.
- `shared_invariants.py` — Cross-organization invariant library.
  Organizations publish anonymized rules; others import them.
- `profile_export.py` — Anonymized fingerprint export for
  marketplace contribution.

## Privacy Guarantee
No `agent_id`, no `execution_trace`, no raw `arguments` or
`capability` payloads leave the premises. Only statistical
patterns and policy rules are shared.

## Enterprise Integration
Organizations can subscribe to marketplace patterns via:
- Local adapter (`agent_dna/adapters_policy/local.py`)
- Git bundle (`agent_dna/adapters_policy/git_bundle.py`)
- OPA connector (`agent_dna/adapters_policy/opa.py`)

## Metric Target
Network effect activates when cross-organization invariant
library exceeds 1,000 published patterns and aggregate analytics
cover >100,000 anonymized decisions.
