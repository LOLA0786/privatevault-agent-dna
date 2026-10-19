# 0024: A permit never outlives the authority behind its ALLOW

Status:     accepted
Date:       2026-10-19
Pinned by:  tests/test_authority_freshness.py::test_mint_after_approval_expiry_is_refused;
            tests/test_authority_freshness.py::test_permit_never_outlives_its_approval;
            tests/test_authority_freshness.py::test_mint_after_grant_expiry_is_refused;
            tests/test_authority_freshness.py::test_mint_after_decision_window_is_refused;
            tests/test_authority_freshness.py::test_secure_profile_refuses_mint_after_approval_expiry

## What forced the decision
An external review (19 October 2026, finding 2) reproduced four ways an
ALLOW outlived its authority. Approval and grant validity were checked when
deciding, and never again. A decision approved by a human could be minted a
day after the approval expired, and the receiver admitted the fresh permit.
A permit's expiry was mint time plus the permit lifetime, so it could end
after its approval. An ALLOW whose grant had since expired could still be
minted. The secure profile changed none of this.

## The decision
At mint, `/v1/authorize` computes the end of the authority behind the
decision (`agent_dna/authority_deadline.py`), the earliest of:

1. the decision's mint window: the record's sealed, server-set `timestamp`
   plus `PV_DECISION_MINT_WINDOW_SECONDS` (default 300, 1 to 3600). The
   caller's action timestamp is never used;
2. for an approval-triggered ALLOW, the verified approval artifact's
   `expires_at`. The approval bridge stores it beside the approval's
   single-use claim (`approval_consume.not_after`) when it verifies the
   artifact, so every instance sharing the database sees it after restart;
3. for a grant-backed ALLOW, the grant's `expires_at`, looked up by the
   grant id sealed in the record. Grant ids are stable across restarts and
   instances because they derive from the grants file.

At or after that end the mint is refused with `AUTHORIZE_AUTHORITY_EXPIRED`
and the reason names which limit ended it. Otherwise the permit's
`expires_at` is the earlier of the permit lifetime and that end, rounded
down to the whole second permits use. The sidecar and the receiver already
refuse an expired permit, so they enforce the same end without changes.

An end that cannot be established refuses with
`AUTHORIZE_AUTHORITY_UNKNOWN`: an approval with no stored expiry (claims
recorded before this change), a grant id the registry no longer holds (the
grant was removed from configuration), a record without a server timestamp.

The sealed record format is unchanged: no new field in DRP, no Rust or
verifier change.

## What this costs us
- An ALLOW is usable for minting for five minutes by default. A workflow
  that decides early and executes much later must decide again, or raise the
  window (at most an hour).
- Decisions approved before this change cannot mint after upgrade; their
  approval claims have no stored expiry. Decide again.
- Removing a grant from the grants file stops its outstanding ALLOWs from
  minting, which is intended, but a mistaken edit does the same.
- Only expiry, revocation and removal end authority. A changed policy file,
  changed enterprise state or a tightened grant budget does not invalidate
  ALLOWs already made; they stay mintable until their deadline. That is the
  reason the window is short.

## What would make us revisit
Workflows that need long-lived execution authority (then a signed,
renewable authority with explicit re-check, not a longer window), or a
requirement that policy changes invalidate outstanding decisions at once
(then a policy version sealed with each decision and checked at mint).
