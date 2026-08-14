# Fineract integration pilot — task brief

## Scope
Point the existing exact-byte HTTP adapter at a locally-run Apache Fineract
instance and prove four refusals against an INDEPENDENT system of record.

Upstream: github.com/apache/fineract (Apache-2.0). Pinned by tag in
compose file. Do NOT vendor, fork, or patch Fineract. It is the counterparty,
not a dependency.

## Non-goals — do not do these
- Do not modify agent_dna/connector/adapters/exact_byte_http.py to accommodate
  Fineract. If it needs changing, stop and report why.
- Do not add Fineract to install_requires or any runtime dependency.
- Do not write mocks. Rule 1 applies: the pilot is worthless with a fake core.
- Do not touch WHAT-WE-DO-NOT-CLAIM.md except as specified below.

## Deliverables
1. `pilot/fineract/docker-compose.yml` — pinned Fineract + Postgres, one command up.
2. `pilot/fineract/seed.py` — creates two clients, two savings accounts, funds
   account A. Idempotent. Fails loudly if the API shape differs from expected.
3. `tests/pilot/test_fineract_enforcement.py` — marked `@pytest.mark.pilot`,
   skipped by default, run in a separate CI job with the container up.
4. `pilot/fineract/README.md` — how to run, and what it does not prove.

## The four cases — each asserts against Fineract's ledger, not ours
Every test must end by querying Fineract directly and asserting the balance
that Fineract believes. "PrivateVault says it blocked" is not an assertion.

1. payload_mutated_after_allow
   Authorize transfer of 500 from account A to account B. Mutate the
   destination to account C between ALLOW and egress. Assert: connection never
   opened, action_digest mismatch recorded, Fineract balances all unchanged.

2. permit_replay
   Authorize and execute one transfer of 100 (this one SUCCEEDS — Fineract
   must show the money moved). Replay the same permit. Assert: second attempt
   refused at the consume ledger, Fineract shows exactly one transfer.

3. budget_exhausted_across_agents
   Two agents share a daily budget of 1000. Agent one moves 900. Agent two
   attempts 200. Assert: refusal at the group breaker, Fineract total moved
   is exactly 900.

4. chain_verifies_independently
   Export the decision chain and run tools/verify_records.py in a subprocess
   with no agent_dna import. Assert: verdict clean, and the set of
   action_digests that reached dispatch equals the set of transfers present in
   Fineract's transaction list. Divergence in either direction is a failure.

## Verify before coding — do not assume these
Read the pinned Fineract docs/source and confirm, then record the answers in
pilot/fineract/README.md:
- base path and port (self-signed TLS is expected — do not disable
  verification globally, pin the cert)
- tenant header name and default tenant id
- default credentials and how to change them in compose
- the exact endpoint and request body for an account-to-account transfer
- the endpoint to read a savings account balance and transaction list
If any of these differ from what the task assumed, follow the source, not
this brief.

## Honesty requirements — same commit, not a follow-up
- WHAT-WE-DO-NOT-CLAIM.md: replace the "no core banking system" line with the
  narrowed version. It must still say: open-source core in a lab, single
  instance, no production data, no Tier-1 deployment, no regulator has
  reviewed it.
- usecases.yaml: the banking case cites the new test file with its real
  collected count.
- README claim table: one row, naming the test, no adjectives.

## Definition of done
`docker compose up -d && pytest -m pilot` passes from clean, twice in a row,
on a machine that has never run it before.

## Removability — this must stay deletable

The pilot is an experiment with an expiry date, not a feature. It is correct
only if it can be removed in one commit that touches nothing load-bearing.

### Containment
Everything the pilot adds lives in exactly three paths:
- `pilot/fineract/`
- `tests/pilot/`
- `docs/pilot/`
Plus at most: one `pilot` marker in pyproject/pytest.ini, one optional
dependency group named `pilot`, one CI job named `pilot`. Nothing else.

### One-way dependency, machine-checked
`pilot/` and `tests/pilot/` may import `agent_dna`. Nothing under `agent_dna/`,
`api/`, `tools/` or `tests/` (outside `tests/pilot/`) may reference `pilot`,
`fineract`, or `seabaas` in any form — import, string, config key, comment.

Add `tests/test_pilot_isolation.py` (NOT under tests/pilot — it must survive
the deletion and then pass trivially):

    def test_core_does_not_reference_pilot():
        """The Fineract pilot is deletable. Nothing in the product may know it exists."""

Grep the source tree, assert zero hits. Follow the documented lesson: match on
import statements and identifiers parsed from the AST, not on keyword guesses.

### No shared fixtures
`tests/pilot/` gets its own `conftest.py`. Do not add Fineract fixtures,
markers, skips, or env vars to the root `tests/conftest.py`. If a pilot test
needs a helper that already exists in the suite, copy it into `tests/pilot/`.
Duplication is cheaper than a seam through the shared fixture file.

### Dependencies
Fineract client deps go in an optional group `pilot` only. `pip install -e .`
with no extras must still work with `pilot/` deleted and with it present.

### CI
Separate job, `continue-on-error: false` but not required for merge on the
main branch protection rule. The main test job must never start a container.
If the pilot job is deleted, the main job is unaffected.

### The removal procedure — write it, and prove it
`pilot/fineract/README.md` ends with a REMOVAL section stating exactly:

    rm -rf pilot/ tests/pilot/ docs/pilot/
    # then revert, in the same commit:
    #   WHAT-WE-DO-NOT-CLAIM.md  -> restore "no core banking system" line
    #   usecases.yaml            -> drop the Fineract evidence entry
    #   README claim table       -> drop the row
    #   pyproject.toml           -> drop the 'pilot' extra and marker
    #   .github/workflows        -> drop the 'pilot' job
    # then: pytest  (must pass, unchanged count minus the pilot tests)

Before the pilot branch merges, run that procedure on a scratch branch and
confirm the suite is green. If removal breaks anything, containment failed —
fix the containment, not the removal steps.

### Expiry
`pilot/fineract/README.md` states a review date. On that date the pilot is
either promoted to a supported integration with its own claim discipline, or
removed. It does not sit undecided. Review date: 31 December 2026.
