# Roadmap and known limitations

Items here are known gaps, stated so a demo or a pilot does not claim them.
Each names the control that exists today and what is missing.

## Receiver gate: presenter identity (shipped, ADR 0022)

Shipped: per-agent mTLS client certificates, the key pinned per agent in
`PV_PRESENTER_BUNDLE`, bound into permits (spec 0.2) and checked by the gate
before the ledger. Still open:

- The receiver kit's default container command serves plain HTTP; mTLS is
  `python -m network.receiver_kit.serve` with the three `PV_RECEIVER_TLS_*`
  variables, and the image has not been run with it in CI.
- `PV_SECURE_PROFILE=1` does not yet require a presenter bundle.
- No CRL/OCSP at the gate; a removed key's outstanding permits live until
  expiry (one minute by default).
- The sidecar does not refuse locally when a permit names a different
  presenter; the gate does.
- The treasury demo still uses plain HTTP on loopback.

## Policy replay: library only

`agent_dna.policy_replay.PolicyReplay` re-evaluates a policy over sealed
decisions with opt-in retained inputs (`PV_REPLAY_FIELDS`). There is no
API endpoint; a deployment calls it in process against its stores. The
treasury demo does exactly that.

## Approvals: single pinned approver, no quorum

The approval bridge (ADR 0020) verifies one signed `approval_v01` artifact
from a pinned approver and refuses self-approval
(`APPROVAL_SEPARATION_OF_DUTIES`) and unpinned keys. It does not model
roles, quorum (two of three), or consensus. Not claimed anywhere.

## Not in the product

Sanctions and watchlist screening, beneficiary name matching, and board
approval workflows are outside the product. A hard cap is a block; what
happens above it is the customer's process.
