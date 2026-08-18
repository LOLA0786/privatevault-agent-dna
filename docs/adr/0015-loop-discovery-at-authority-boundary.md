# 0015 — Loop discovery sits at the authority boundary

Status:     accepted
Date:       2026-08-06
Commit:     2baa6c983653c2ffa9daa1a885f327eadaa954a4
Pinned by:  tests/test_authorize_loop_gate.py::test_circular_authority_refuses_authorize

This record was originally `0001-loop-discovery-at-authority-boundary.md`.
It was renumbered when the enforcement-spine series took 0001–0014.

## What forced the decision
Framework-level recursion limits see only one runtime's call stack.
They cannot reliably detect a loop that crosses agents, frameworks,
identities, or tool gateways. A model-based detector would also let
proposal logic influence its own enforcement decision — the same
mistake 0001 refuses on the main path.

## The decision
Loop discovery consumes immutable security events after proposal
translation and authority verification but before consequential
dispatch. The analyzer is deterministic, framework-neutral, bounded,
and independent of the proposing model. Authority cycles block by
definition. Invocation cycles are reviewable until causal repetition,
authorization replay, or malformed lineage provides stronger
evidence. `REVIEW`, malformed input, unavailable controls, and
`BLOCK` are non-executable at the dispatch boundary.

## What this costs us
Complete causal identifiers must propagate across agent boundaries.
Integrators must persist or stream a complete bounded trace window.
Loop discovery complements rather than replaces grant containment,
rate breakers, exact-byte dispatch witnesses, and execution closure.
It does not infer hidden agent activity or prove bytes reached a
peer.

## What would make us revisit
A requirement to detect collusion or bypass that never appears in
the supplied event window — that is an observer outside this
analyzer, not a smarter model inside it. Moving discovery after
dispatch so that "we have more data" would let a looping grant
mint first.
