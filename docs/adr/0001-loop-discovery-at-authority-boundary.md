# ADR 0001: Place loop discovery at the authority boundary

- Status: Accepted
- Date: 2026-08-06

## Context

Framework-level recursion limits see only one runtime's call stack. They cannot
reliably detect a loop that crosses agents, frameworks, identities, or tool
gateways. A model-based detector would also let proposal logic influence its
own enforcement decision.

## Decision

Loop discovery consumes immutable security events after proposal translation
and authority verification but before consequential dispatch. The analyzer is
deterministic, framework-neutral, bounded, and independent of the proposing
model.

Authority cycles block by definition. Invocation cycles are reviewable until
causal repetition, authorization replay, or malformed lineage provides stronger
evidence. `REVIEW`, malformed input, unavailable controls, and `BLOCK` are
non-executable at the dispatch boundary.

## Consequences

- The same event bytes produce the same report across model routes.
- Framework adapters remain translation-only and credential-free.
- Complete causal identifiers must propagate across agent boundaries.
- Loop discovery complements rather than replaces grant containment, rate
  breakers, exact-byte dispatch witnesses, and execution closure.
- Integrators must persist or stream a complete bounded trace window.
