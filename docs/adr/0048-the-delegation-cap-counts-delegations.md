# 0048: The delegation cap counts delegations

Status:     accepted
Date:       2026-11-24
Pinned by:  tests/multi_agent_security/test_delegation.py::test_the_cap_counts_delegations;
            tests/multi_agent_security/test_delegation.py::test_depth_is_bounded;
            tests/test_aat02_vectors.py::test_every_vector_agrees (PV.17, PV.36)

## What forced the decision
pv-delegation/2 counted depth two ways. The limit a link carries
(`max_depth`, ADR 0042) counts delegations: a root with `max_depth` 3 admits
three more links, four in all. The fixed cap counted links: `verify_chain`
refused a chain of more than `MAX_DEPTH` (8) links. So a root could carry
`max_depth` 8, the largest value the format allows, and promise eight more
delegations, yet only seven could ever verify; the eighth was refused by the
cap, for a different reason. The AAT -02 vectors (docs/AAT02-VECTORS.md) made
it visible: AAT's reference verifier admits a nine-token chain under a limit
of 8 (constraint-comparison CC-1), and PrivateVault refused it.

## The decision
The cap counts delegations too: a chain is a root and at most `MAX_DEPTH` (8)
delegations below it, so at most nine links (`MAX_CHAIN_LINKS`). Every limit a
link can carry is reachable, and PrivateVault counts depth as AAT -02 does at
every limit, the cap included. The refusal still begins "chain is deeper
than".

The alternative, keeping eight links and lowering the largest `max_depth` to
7, would also have made the two counts agree, but it breaks every v2 link
already signed with `max_depth` 8 and keeps PrivateVault one delegation short
of AAT at the cap.

## What this does not do
- It does not change how `max_depth` narrows, or its range of 0 to 8.
- A chain of version 1 links, which carry no `max_depth`, may now be nine
  links long, one more than before. The cap bounds work and chain size; a
  root that wants fewer hops sets `max_depth`.
- asor -03 counts a limit of 8 as eight tokens. PrivateVault now disagrees
  with asor at the cap, as it already did below it.
