# Invariants

The promises PrivateVault keeps whatever model drives the agent. Models will
keep getting better; none of these depends on a model behaving well. A change
that breaks one is wrong even if every other test passes. Changing a promise
takes an ADR in [docs/adr/](docs/adr/README.md) and a maintainer's sign-off.

Each promise names the tests that enforce it. `tests/test_invariants_doc.py`
fails if a named test disappears, and CI runs them all on every pull request.
Where a promise was broken and then fixed, it says so.

## 1. Models propose; they never authorize

What a model says, what an agent claims, and the learned drift score are
inputs to a decision, never the authority for one. The drift level can send an
action to a person; it can never block one. The attack corpus and the
challenger run every attack as if the agent were hostile.

- Enforced by: `tests/test_precedence_contract.py::test_drift_can_never_block`,
  `tests/demos/test_live_checkout_attacks.py`, `tests/demos/test_challenger.py`

## 2. Doubt means no

A fault in the engine, a malformed or non-finite input, missing or
unverifiable authority, or an unreadable system of record ends in a block,
never an allow.

- Enforced by: `tests/test_fail_closed.py`, `tests/test_api_fail_closed.py`,
  `tests/test_nonfinite_guard.py`,
  `tests/demos/test_live_checkout_facts.py::test_unreadable_source_refuses`

## 3. One fixed order decides

The levels are evaluated in the order pinned in
`spec/contracts/precedence-order.json`; the first level that fires decides,
and a block is final. Code, contract and documentation cannot drift apart.

- Enforced by: `tests/test_precedence_contract.py`,
  `tests/test_architecture_doc.py::test_precedence_table_equals_pinned_contract`

## 4. A permit covers these exact bytes, once

An allowed action that changes something gets a signed, single-use permit for
the exact bytes decided. A changed byte, amount or payee is refused at the
sidecar and at the receiver gate; replays, races and retries end in at most
one admission and one payment.

- Enforced by: `tests/test_wire_action_binding.py`,
  `tests/demos/test_live_checkout_attacks.py`,
  `tests/demos/test_challenger.py::test_no_money_moves_and_the_oracle_can_see`

## 5. A refused decide keeps nothing

A block or a hold moves no money, and gives back the grant spend and the
transaction reservation claimed while deciding. So does a decide that fails
partway, which also fails closed.

- Enforced by: `tests/demos/test_live_checkout_grant_spend.py::test_refused_decides_give_back_the_grant_spend`,
  `tests/demos/test_challenger.py::test_refused_decides_do_not_spend_the_grant`,
  `tests/test_decide_reservation.py::test_release_only_drops_an_unsealed_hold`,
  `tests/test_decide_fault_releases_claims.py::test_fault_before_the_seal_releases_the_reservation`
- Broken once: refused decides kept their grant spend until ADR 0046. The
  continuous challenger found it.

## 6. Rules read facts from the system of record, not from the agent

Where a fact source is configured (ADR 0045), the order amount, payee and
prior refunds a rule depends on are read from the system of record at decide
time, and a stated fact that differs is a block.

- Enforced by: `tests/test_fact_sources.py`,
  `tests/demos/test_live_checkout_facts.py::test_false_facts_are_refused`,
  `tests/demos/test_live_checkout_facts.py::test_refund_during_approval_wait_is_caught`

## 7. Authority only narrows, and limits hold under concurrency

Authority delegated from one agent to another never exceeds its parent's
budget, argument values or depth (ADR 0042, when `PV_DELEGATION_FILE` is set).
Daily count and amount limits are claimed atomically on the server (ADR
0043), so parallel requests cannot split their way past them.

- Enforced by: `tests/multi_agent_security/test_delegation_v2.py::test_server_budget_is_cumulative`,
  `tests/multi_agent_security/test_delegation_v2.py::test_server_sibling_race`,
  `tests/test_decide_limits.py::test_server_count_limit_holds`,
  `tests/demos/test_live_checkout_limits.py::test_parallel_smurfing_pays_three`

## 8. Every decision is evidence anyone can check, for years

Each decision is sealed into a signed, hash-chained record. A verifier that
needs only the Python standard library, and imports nothing from this code,
checks it; an edited, deleted or divergent record fails. The committed vectors
in `spec/test-vectors/` must keep verifying, so a record format never breaks.

- Enforced by: `tests/test_verifier_independence.py::test_independent_verifiers_have_no_repository_imports`,
  `tests/test_verifier_runs_on_stdlib.py`,
  `tests/test_fail_closed.py::test_fault_result_is_still_a_valid_sealable_record`,
  and the CI step that verifies `spec/test-vectors/`

## 9. A claim names its test

Every product claim in the documentation cites a test or a verifiable
artifact; what cannot be shown goes in `docs/WHAT-WE-DO-NOT-CLAIM.md`.

- Enforced by: `tests/test_docs_structure.py::test_claim_pages_cite_real_files_and_tests`,
  `tests/test_claim_counts.py`, `tests/test_invariants_doc.py`
