# 0003 — Authorization and execution are bound by action_digest (DRP 0.2)

Status:     accepted
Date:       2026-08-10
Commit:     1692f4ec3de9dae4c76831248a7baccd08824839
Pinned by:  tests/test_pv001_drp02_authorize.py::test_drp01_record_cannot_mint

## What forced the decision
DRP 0.1 sealed an ALLOW that named a capability and hashed arguments.
Mint then trusted the caller to present "the" action. That is tempting
because it keeps `/v1/decide` small and does not break clients that
already stored 0.1 records. It is also how a sealed ALLOW for
`crm.read` is spent as a wire: the permit is not bound to the bytes
that will run.

The other tempting shortcut was to add an `action_digest` field and
keep `build_record` on 0.1, or to accept a caller-supplied digest on
decide. A field that the caller chooses is not a binding.

## The decision
Live decide emits DRP 0.2. The runtime derives `action_digest` and
`dispatch_context_digest`; callers cannot stuff either. `/v1/authorize`
refuses DRP 0.1, refuses a non-ALLOW, and recomputes the digest against
the sealed record and the mint request. Execution verification compares
that digest to the observed action. Compatibility with 0.1 as a mint
source is a break, not a flag.

## What this costs us
Every client that assumed a 0.1 ALLOW could mint must migrate.
Decide must carry or derive a full canonical execution action, not
just a capability string. Wire and peer digests are still not sealed
at decide time; that residual is documented, not silently stuffed
into `action_digest`.

## What would make us revisit
A versioned widening of the canonical action frozenset (destination,
wire intent) shipped as DRP 0.3 with a categorical mint refusal of
0.2 for that new binding — not a silent extra field. Re-enabling 0.1
mint for "legacy partners" is not a trigger; it reopens PV-001.
