# Roadmap and known limitations

Items here are known gaps, stated so a demo or a pilot does not claim them.
Each names the control that exists today and what is missing.

## Receiver gate: presenter identity (per-agent mTLS client certificates)

**Today.** A permit is bound to the requesting agent's subject principal
and key id, the exact action, and the exact wire bytes. The agent's own
sidecar verifies a permit against the action it is about to dispatch, so a
permit minted for agent A cannot be used by agent B's sidecar for B's
action (`EXECUTION_AUTHORIZATION_NON_CONFORMANT`). The receiver gate
verifies the permit's signer against its pinned bundle, the organisation,
the audience (the receiver), destination, operation, validity window, the
exact bytes, and single use through its own ledger.

**Gap.** The gate does not authenticate who presents a permit. A process
that obtains agent A's permit and A's exact bytes can present them to the
gate once if A has not already sent them; the gate admits them because
they are exactly what A was authorised to send. The demo transport is
plain HTTP on loopback with a fixed peer label; the production transport
derives the receiver's identity from the TLS handshake but there is no
client identity in the other direction.

**Planned.** Per-agent mTLS client certificates, with the client
certificate's identity bound into the permit (`expected_presenter_identity`
alongside `expected_peer_identity_digest`) and checked by the gate before
the ledger. Until then: keep permits and wire bytes inside the sidecar
process, keep the gate's validity window short (one minute today), and
treat the sidecar's conformance check as the per-agent control.

Shown honestly in `demos/treasury/` (action #16): the sidecar refusal and
the consumed refusal are demonstrated; a presenter check is not claimed.

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
