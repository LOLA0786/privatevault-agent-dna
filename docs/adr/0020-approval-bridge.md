# 0020: A verified, single-use approval satisfies REQUIRE_APPROVAL (approval bridge)

Status:     accepted
Date:       2026-10-12
Pinned by:  tests/test_approval_bridge.py::test_approval_is_consumed_atomically_and_durably;
            tests/test_approval_bridge.py::test_approver_must_differ_from_requester;
            tests/test_api_approval_bridge.py::test_approved_decide_mints_a_permit_bound_to_the_approval

## What forced the decision
The engine's policy and authorization levels return REQUIRE_APPROVAL, the
API answers 202, and there the product stopped. `approval_v01` already
defined an immutable approval request, a signed approval artifact, and an
approver authority receipt, and `/v1/authorize` already accepted an
`approval_artifact_digest`, but nothing consumed a human's answer to turn
the 202 into an ALLOW that could mint. The LangGraph example (#107)
bridged the gap with a throwaway grant on an in-process engine and
listed that as its first integration finding. Every customised agent
would otherwise reinvent that bridge, each one differently.

## The decision
`/v1/decide` accepts an optional `approval` block carrying the three
`approval_v01` objects. `DecisionEngine` gains one step, applied only when
the verdict is REQUIRE_APPROVAL from the policy or authorization level:
`ApprovalBridge.consider` admits the approval only if all of the following
hold, in this order, each refusing with its own reason code:

1. the artifact verifies against the operator-pinned approver trust bundle
   (`PV_APPROVER_TRUST_BUNDLE`, keys with usage `approval_signer`) through
   `verify_approval_for_execution`, unchanged: signature, key usage, the
   approver's authority receipt, validity windows, decision APPROVE;
2. the approval's `action_digest` equals the digest of the execution action
   being decided, and the organisation matches the bundle;
3. the approval names this agent as the subject;
4. separation of duties: the approver principal and key id are not the
   requesting agent, its principal, or the authenticated caller;
5. the artifact digest is claimed in the durable ledger with the same
   `BEGIN IMMEDIATE` + primary key construction as permits (ADR 0004); a
   second claim is refused.

On success the result becomes ALLOW with `triggered_by = "approval"` and the
artifact digest sealed into the record's schema-reserved `approval_ref`.
`/v1/authorize` then mints only if the request names that exact digest,
so the permit's `approval_artifact_digest` is the approval that produced
the ALLOW.

Refusals never change the verdict: the decision stays REQUIRE_APPROVAL
with the refusal appended to its reason, and a refused approval is not
consumed. An approval never overrides BLOCK and is never consumed by a
decision that was already ALLOW. Drift, consensus, and economics
escalations are not satisfiable by an approval here. The bridge judges
validity by its own clock, never by anything the caller sends.

An approval block presented when no approver bundle is pinned, or on an
audit-only decide (no execution action), is refused outright with 422
before any decision is made.

## What this costs us
- The approver's authority receipt must be a real `authority_v01` receipt
  whose grant chain descends from a root in the approver bundle. Approval
  tooling has to produce one; a bare signature is not an approval.
- Single use is per artifact. Approving the same action twice requires two
  artifacts. There is no partial or multi-use approval.
- A claimed approval whose decision record then fails to persist is burned
  (ADR 0005 applies). Recovery is a new artifact.
- The approver bundle is a second pinned trust root to rotate; rotation is
  a hard cutover like the execution bundle.
- Separation of duties is checked against identity strings the deployment
  supplies (agent id, principal, caller fingerprint). It cannot see a human
  who holds two credentials.

## Known limitations
- The approval is consumed at decide time. If no permit is minted
  afterwards (the caller never calls `/v1/authorize`, or the mint is
  refused), the approval is spent and must be re-issued. This is
  fail-closed by design: an approval that could be re-presented after a
  failed mint could also be re-presented after a successful one.

## What would make us revisit
A request to let a drift or consensus escalation be approved (a different
risk class, needs its own rule). A multi-approver quorum (one artifact per
approver would compose; the engine would need a count). Any proposal to
accept an approval whose action digest is computed by the caller.
