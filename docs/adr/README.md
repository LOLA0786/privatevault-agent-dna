# Architecture decision records

Numbered decisions that will look optional in a decade unless the
rejected alternative and its cost are written down. Code shows
what we do. These files show why we refused the other thing.

Format: `NNNN-short-slug.md`. Status is `accepted`, `open`,
`proposed`, or `superseded by NNNN`. `Pinned by` is a real
`path::test_name` that fails if the decision is undone, or an
explicit statement that no such test exists.

| ID | Decision | Status | Pin |
|----|----------|--------|-----|
| [0001](0001-enforcement-boundary-is-the-action.md) | The enforcement boundary is the action, not the model | accepted | `tests/test_precedence_contract.py::test_drift_can_never_block` |
| [0002](0002-decision-path-deterministic-fail-closed.md) | The decision path is deterministic and fail-closed | accepted | `tests/test_fail_closed.py::test_raising_scorer_fails_closed` |
| [0003](0003-authorization-bound-by-action-digest.md) | Authorization and execution are bound by action_digest (DRP 0.2) | accepted | `tests/test_pv001_drp02_authorize.py::test_drp01_record_cannot_mint` |
| [0004](0004-permits-single-use-durable-ledger.md) | Permits are single-use against a durable ledger | accepted | `tests/test_consume_ledger.py::test_second_verify_refused_as_consumed` |
| [0005](0005-burned-permit-is-not-retried.md) | A permit burned by transport failure is not retried | accepted | `tests/connector/test_exact_byte_http.py::test_transport_write_then_raise_is_indeterminate` |
| [0006](0006-indeterminate-is-first-class.md) | INDETERMINATE is a first-class outcome, not an error | accepted | `tests/test_execution_feedback.py::test_indeterminate_is_not_ok_and_not_divergence` |
| [0007](0007-execution-trust-bundle-deployment-pinned.md) | The execution trust bundle is deployment-pinned, not caller-supplied | accepted | `tests/connector/test_exact_byte_http.py::test_attacker_controlled_trust_bundle_never_sends` |
| [0008](0008-dispatch-witness-signed-after-send.md) | The dispatch witness is signed after send, never before | accepted | `tests/connector/test_exact_byte_http.py::test_callback_sending_different_bytes_is_not_executed` |
| [0009](0009-key-may-not-mint-and-witness.md) | A key may not both mint permits and witness them | accepted | `tests/test_dispatch_v01.py::test_same_public_key_is_not_independent` |
| [0010](0010-secure-profile-refuses-allow-no-auth.md) | PV_SECURE_PROFILE refuses PV_ALLOW_NO_AUTH rather than warning | accepted | `tests/test_secure_profile.py::test_secure_profile_refuses_allow_no_auth` |
| [0011](0011-every-claim-pinned-to-named-test.md) | Every claim is pinned to a named test, count enforced in CI | accepted | `tests/test_claim_counts.py::test_documented_test_count_matches_reality` |
| [0012](0012-python-rust-ci-parity.md) | Python and Rust maintain CI parity | accepted | `rust/tests/canonical_parity.rs::float_repr_matches_cpython` |
| [0013](0013-open-core-split.md) | Open-core split: drp-spec Apache-2.0, runtime commercial | accepted | no pinning test for the commercial license (verifier independence is pinned; see ADR) |
| [0014](0014-peer-identity-format.md) | Peer identity format for the production TLS sidecar | open | no pinning test |
| [0015](0015-loop-discovery-at-authority-boundary.md) | Loop discovery sits at the authority boundary | accepted | predates this series; see that file |
| [0016](0016-one-live-permit-per-decision.md) | One live stored permit per decision | accepted | `tests/test_authorize_mint_claim.py::test_sequential_mint_returns_byte_identical_authorization` |
| [0017](0017-wire-action-binding.md) | Trusted action↔wire binding at authorize | accepted | `tests/test_wire_action_binding.py` |
| [0019](0019-receiver-gate.md) | The system of record verifies the permit (receiver gate) | accepted | `tests/receiver/test_receiver_gate.py::test_direct_call_without_permit_is_refused` |
| [0020](0020-approval-bridge.md) | A verified, single-use approval satisfies REQUIRE_APPROVAL | accepted | `tests/test_approval_bridge.py::test_approval_is_consumed_atomically_and_durably` |
| [0021](0021-server-derived-lineage.md) | Multi-agent dual control runs on server-derived lineage, not a caller-chosen id | accepted | `tests/test_lineage_dual_control.py::test_split_execution_ids_no_longer_bypass` |
| [0024](0024-permit-never-outlives-its-authority.md) | A permit never outlives the authority behind its ALLOW | accepted | `tests/test_authority_freshness.py::test_mint_after_approval_expiry_is_refused` |
| [0025](0025-capabilities-declare-their-operations.md) | A capability covers only the operations the operator declared | accepted | `tests/test_operation_registry.py::test_read_grant_cannot_obtain_a_transfer_permit` |
| [0026](0026-permit-evidence-is-the-servers.md) | The evidence a permit cites is the server's, not the caller's | accepted | `tests/test_permit_evidence.py::test_secure_profile_refuses_the_reviews_probe` |
| [0027](0027-receiver-kit-hardened-by-default.md) | The receiver kit is hardened by default | accepted | `tests/network/test_receiver_hardened.py::test_unreachable_api_ends_in_refusals_not_admissions` |
| [0028](0028-secure-profile-binds-presenters.md) | The secure profile binds every permit to its presenter | accepted | `tests/test_secure_profile_presenters.py::test_default_receiver_admits_only_the_bound_agent` |
| [0029](0029-routine-reads-are-indexed-queries.md) | Routine reads are indexed queries, one page at a time | accepted | `tests/test_indexed_reads.py::test_api_reads_never_load_the_whole_ledger` |

0001–0014 are the enforcement-spine decisions. 0015 is the earlier
loop-discovery placement record, renumbered so the spine could own
0001. 0016 is the mint-claim ledger that makes one ALLOW mint at most
one live stored permit. 0017 closes the first-mint action≠wire gap
by binding expected wire bytes to a named serialization of the sealed
action.
0019 moves permit verification and single-use consumption to the
system of record, so an agent that calls a gated API directly is refused
by the API's own front door. 0018 is the separately proposed swarm-controls
plan. 0020 lets a verified, single-use human approval turn a policy or
authorization REQUIRE_APPROVAL into an ALLOW bound to the same action, with
separation of duties, so the permit names the approval that produced it.
0021 moves maker != checker from a caller-chosen execution id to lineage the
server records itself, so splitting, flooding or evicting a correlation window
no longer lets one agent approve its own initiate.
0022 binds a permit to the TLS client key that may present it and has the
receiver gate check that key over mTLS, so a stolen permit and its bytes are
refused from any other process.
0023 lets every signing key live in AWS KMS or Google Cloud KMS, with
signatures identical to local signing and each one verified before use.
0024 ends minting when the approval, grant or decision window behind an
ALLOW ends, and caps every permit's expiry at that end.
0025 makes the operator declare the exact operations each capability
covers; anything else is a sealed BLOCK at decide and refused at mint.
0026 seals the policy bundle and grant behind each decision and signs those
into the permit, not the caller's digests.
0027 makes the receiver kit's defaults the hardened deployment: mutual TLS,
presenters required, and a refreshed revocation list it fails closed on.
0028 makes the secure profile require a presenter bundle and provisions one
client certificate per agent, so every permit names who may present it.
0029 answers routine reads with indexed, paginated queries instead of
loading the whole ledger, and seal-checks every record it serves.
