# Threat model, indexed by attack

`docs/SECURITY.md` describes the security model from the defender's side:
adversaries, defenses, trust assumptions, residual risks. This document
is the other index: one row per attack, the control that stops it, the
ADR that decided the control, and the test that fails if the control is
removed. `tests/proof/test_docs_pin_tests.py` fails if any test named here
stops existing, so this table cannot quietly go stale.

The setting throughout: an agent holds valid credentials for a system of
record. The model proposes actions; PrivateVault decides them; money
actions execute only through a single-use permit bound to the exact bytes,
which the receiver gate at the system of record verifies and consumes.

## Attacks

| Attack | Where it is stopped | Control | Evidence |
|---|---|---|---|
| Amount changed after approval, inside the agent process | Sidecar refuses before any byte; receiver gate refuses if the sidecar is bypassed | Permit binds the exact wire bytes (ADR 0017); receiver verifies them (ADR 0019) | `tests/connector/test_exact_byte_http.py::test_mutated_payload_never_calls_send`, `tests/receiver/test_receiver_gate.py::test_amount_swap_refused`, `tests/agents/test_finance_ops.py::test_amount_change_after_approval_is_refused_twice`, `tests/proof/test_compare.py::test_amount_change_passes_three_controls_and_is_refused_by_the_gate` |
| Payee changed after approval | Same two places | Same | `tests/receiver/test_receiver_gate.py::test_payee_swap_refused`, `tests/proof/test_injection.py::test_payee_injected_after_approval_is_refused`, `tests/agents/test_property_broker.py::test_payee_change_after_approval_is_refused` |
| Direct call to the system of record with credentials and no permit | Receiver gate | Verification at the system of record (ADR 0019) | `tests/receiver/test_receiver_gate.py::test_direct_call_without_permit_is_refused`, `tests/receiver/test_receiver_http.py::test_proxy_blocks_bypass_and_forwards_permitted_call_once` |
| Replay of a consumed permit, including concurrent replays | Receiver ledger and sidecar ledger | Single-use against a durable ledger (ADR 0004, ADR 0019) | `tests/receiver/test_receiver_gate.py::test_replay_refused_by_receiver_ledger`, `tests/receiver/test_receiver_gate.py::test_concurrent_admit_exactly_once`, `tests/test_consume_ledger.py::test_second_verify_refused_as_consumed` |
| Permit minted for another receiver or route presented here | Receiver gate | Audience and operation bound into the permit (ADR 0019) | `tests/receiver/test_receiver_gate.py::test_audience_mismatch_refused`, `tests/receiver/test_receiver_gate.py::test_wire_action_mismatch_refused` |
| Attacker-supplied trust bundle, peer, or send callback at dispatch | Sidecar | Deployment-pinned trust bundle (ADR 0007) | `tests/connector/test_exact_byte_http.py::test_attacker_controlled_trust_bundle_never_sends`, `tests/connector/test_exact_byte_http.py::test_caller_supplied_peer_identity_is_refused` |
| Expired permit presented with a caller-stated earlier time | Sidecar | Validity judged by the sidecar's own clock (SECURITY.md, fixed issues) | `tests/connector/test_exact_byte_http.py::test_expired_permit_refused_even_when_caller_claims_earlier_time` |
| One changed wire byte, forged witness, or changed observed destination | Dispatch verification | Witness signed after send over what was observed (ADR 0008) | `tests/test_dispatch_v01.py::test_one_changed_wire_byte_blocks_dispatch`, `tests/test_dispatch_v01.py::test_forged_witness_signature_is_invalid`, `tests/test_dispatch_v01.py::test_changed_observed_destination_blocks_dispatch` |
| Second permit for the same decision, including a mint race | Mint claim ledger | One live permit per decision (ADR 0016) | `tests/test_authorize_mint_claim.py::test_sequential_mint_returns_byte_identical_authorization`, `tests/test_authorize_indeterminate_race.py::test_concurrent_claims_converge_on_one_permit` |
| Approval reused for a second ALLOW or a second permit | Approval bridge | Single-use approvals (ADR 0020) | `tests/test_approval_bridge.py::test_approval_is_consumed_atomically_and_durably`, `tests/test_api_approval_bridge.py::test_approval_reuse_yields_no_second_permit` |
| Agent approves its own action, or the caller is the approver | Approval bridge | Separation of duties (ADR 0020) | `tests/test_approval_bridge.py::test_approver_must_differ_from_requester`, `tests/test_api_approval_bridge.py::test_self_approval_is_refused` |
| Approval for action X presented for action Y; expired approval; approver not in the pinned bundle; forged signature | Approval bridge | Approval bound to the exact action digest and verified against the pinned approver bundle (ADR 0020) | `tests/test_approval_bridge.py::test_approval_for_other_action_is_refused`, `tests/test_approval_bridge.py::test_expired_approval_is_refused`, `tests/test_approval_bridge.py::test_unpinned_approver_is_refused` |
| Approval presented when no approver bundle is pinned | API | Refused outright, no decision recorded (ADR 0020) | `tests/test_api_approval_bridge.py::test_approval_block_refused_when_no_bundle_is_pinned` |
| Prompt injection in an invoice rewrites the payee; the model obeys | Decide (policy), then sidecar and receiver if injected later | Vendor master as policy; permit binding | `tests/proof/test_injection.py::test_injected_payee_is_blocked_at_decide`, `tests/proof/test_injection.py::test_model_follows_the_injection` |
| Amount above a hard cap, with or without an approval | Decide | Customer policy `block` is not approvable (ADR 0020) | `tests/agents/test_finance_ops.py::test_unknown_payee_and_hard_cap_are_blocked`, `tests/test_approval_bridge.py::test_approval_cannot_override_block_and_is_not_burned_on_allow` |
| Valid permit dispatched after the agent was suspended | Sidecar, inside the consume transaction | Suspension checked with the claim (ADR 0018) | `tests/test_suspension.py::test_dispatcher_refuses_before_send_for_a_suspended_agent`, `tests/test_suspension.py::test_no_claim_started_after_a_committed_suspension_succeeds` |
| Oversize body or thousands of nested brackets | Request bounds middleware and library depth bound | Bounded before parsing | `tests/test_request_bounds.py::test_oversize_body_is_413`, `tests/test_request_bounds.py::test_deep_nesting_is_refused_on_decide`, `tests/test_json_depth_bound.py::test_receiver_refuses_deep_permit_header_as_malformed` |
| Mint key used as its own dispatch witness | Startup | A key may not both mint and witness (ADR 0009) | `tests/test_secure_profile.py::test_execution_bundle_refuses_mint_key_as_its_own_witness` |
| Receiver receipt tampered or signed with another key | Independent verifier | Receiver-operator receipts, hash-chained (ADR 0019) | `tests/network/test_receiver_kit.py::test_export_and_independent_verifier`, `tests/receiver/test_receiver_independent_verifier.py::test_cli_verifies_real_ledger_in_isolation` |

## Evidence

Run the pinning tests:

```sh
uv run pytest -q tests/receiver tests/connector/test_exact_byte_http.py tests/test_approval_bridge.py tests/test_api_approval_bridge.py tests/proof tests/agents
```

Run the proofs end to end (`proof/README.md`):

```sh
docker compose -f proof/docker-compose.yml up --build --abort-on-container-exit
```

`tools/prove.py` runs the full suite plus the adversarial set and seals a
proof-of-run; `tools/verify_receiver_receipts.py` verifies a receiver's
receipt chain without importing this package.

## Non-goals

Stated so nobody reads more into the table than it says.

- Complete mediation of raw sockets. An agent that never calls the
  sidecar and whose network can reach the upstream directly is stopped
  only if the upstream sits behind a receiver gate. Making the gate the
  sole network path is a deployment property.
- A compromised receiver operator or receiver receipt key. Receipts prove
  what the gate admitted; they are the receiver's own statement.
- Model quality. The proofs use scripted models on purpose; nothing here
  claims a model cannot be talked into proposing a bad action. The claim is
  that proposing it does not move money.
- Durable grant budgets. The cumulative budget is held in process and
  resets on restart (`docs/WHAT-WE-DO-NOT-CLAIM.md`).
- Multi-host single-use. The ledgers are single SQLite files.
- TLS peer identity in the demos. The demo transport uses a fixed label;
  the production transport derives peer identity from the handshake.
- One human holding two credentials. Separation of duties compares
  identity strings the deployment supplies.
- Multi-approver quorum, and approval of drift, consensus, or economics
  escalations.
- What the upstream does after admission. Reconciliation against the
  system's own ledger is separate.
