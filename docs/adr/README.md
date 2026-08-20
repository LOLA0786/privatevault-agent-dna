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

0001–0014 are the enforcement-spine decisions. 0015 is the earlier
loop-discovery placement record, renumbered so the spine could own
0001. 0016 is the mint-claim ledger that makes one ALLOW mint at most
one live stored permit.
