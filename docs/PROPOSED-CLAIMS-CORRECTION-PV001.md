# Proposed claims correction (PV-001) — not applied to marketing docs

This file is a **proposal only**. Marketing / homepage / pitch documents were
not modified in Phase 1.

## Correct claim (after Phase 1 verification)

A sealed DRP 0.2 ALLOW decision binds both:

1. a derive-only `action_digest` over the five-field `action_v01`, and  
2. a derive-only `dispatch_context_digest` over versioned decide-time
   adapter/transport/operation/destination/content-type intent.

`/v1/authorize` refuses DRP 0.1 records and refuses minting when either digest
is missing or does not match an independent server-side recomputation. Caller-
authored digests are not accepted as proof.

## Claims that remain false / out of scope

- Exact wire-byte enforcement at decide time  
- Protection of custom / non-reference transports  
- Automatic rejection of all caller governance digests (Phase 2)  
- Consume-before-send / single-remit product completeness beyond the durable
  consume ledger already present  
- Readiness for shadow or production deployment without Phases 2+  

## Suggested replacement language

Prefer: “Mintable decisions seal derived action and dispatch-context digests;
authorize re-verifies both before signing a permit.”

Avoid: “End-to-end exact-byte execution control” or “all transports protected”
until later phases have executable evidence.
