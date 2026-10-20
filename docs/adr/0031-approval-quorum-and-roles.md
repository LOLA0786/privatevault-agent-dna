# 0031: N distinct approvers, by role, satisfy an approval

Status:     accepted
Date:       2026-10-21
Pinned by:  tests/test_approval_quorum.py::test_two_of_two_with_roles_allows_and_seals_the_set;
            tests/test_approval_quorum.py::test_quorum_refusals_consume_nothing;
            tests/test_approval_quorum.py::test_a_used_approval_burns_none_of_the_others;
            tests/test_approval_quorum.py::test_overlapping_sets_race_to_one_allow;
            tests/test_approval_quorum.py::test_api_quorum_mints_a_permit_naming_the_set

## What forced the decision
ADR 0020 let one signed approval from a pinned approver turn
REQUIRE_APPROVAL into ALLOW. A bank's dual control asks for more: a
payment above a limit needs two people, one of them from a control
function, and never the requester. Retest 5 (20 October 2026) listed
"no quorum, roles, SSO" as the first open enterprise gap.

## The decision
- The operator writes an approval policy (`PV_APPROVAL_POLICY_FILE`,
  `pv-approval-policy/0.1`, example in
  `examples/config/approval-policy.json`): approver principals and their
  roles, and rules per capability (exact name, longest `prefix.*`, then
  `default`). A rule sets `min_approvals` (1 to 10), the `roles` allowed to
  approve, and `require`: roles that distinct people must fill.
- `/v1/decide` accepts `"approval": {"approvals": [...]}`, up to ten
  `approval_v01` triples for the same action. Each is checked exactly as in
  ADR 0020 (signature and key usage against the approver bundle, the
  approver's authority receipt, validity, same action and organisation,
  same subject, separation of duties from the requester). Then the rule
  must hold: every approver listed and holding an allowed role; no person
  twice (principals compared case-folded, so a second key does not make a
  second person); at least `min_approvals`; required roles matched to
  distinct people (one person with two roles fills one slot).
- Identity comes from the approver trust bundle (the key's pinned
  principal); roles come only from the policy file.
- All artifacts and one digest naming the set
  (`pv-approval-set/0.1`: the sorted artifact digests) are claimed in one
  transaction on SQLite and PostgreSQL: all or none. A quorum refused for
  any reason, or one containing a used artifact, spends nothing.
- The decision seals the set digest as `approval_ref`; `/v1/authorize`
  mints only when the request names it, the permit carries it as
  `approval_artifact_digest`, and the permit ends by the earliest
  approval's expiry (ADR 0024).
- The policy file's bytes join the sealed decision configuration
  (ADR 0026), so in server evidence mode a decision made under one policy
  cannot mint after the server loads another.
- Without a policy file, one approval suffices as before and a list of
  several is refused. A policy without an approver bundle stops start-up.

## What this costs us
- Roles live in a file the operator maintains, not in the enterprise
  directory. Someone has to keep it in step with HR changes; a stale file
  lets a person who moved jobs keep approving.
- Every approver needs a key pinned in the approver bundle and an
  authority receipt, as in ADR 0020. There is no approval UI in this
  repository; approval tooling produces the artifacts.
- A person holding two principals (two names in the bundle) counts twice.
  The policy cannot see that.
- Changing the policy file and restarting refuses mints for decisions made
  before the restart, for the mint window (five minutes by default).

## What would make us revisit
Roles and identities from SSO (OIDC/SAML) or SCIM instead of a file;
approval of drift or consensus escalations; per-amount thresholds inside a
capability (today: split the capability, e.g. `payments.pay_invoice.large`).
