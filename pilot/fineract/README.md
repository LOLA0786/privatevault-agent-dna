# Fineract lab counterparty

Apache Fineract is an independent system of record for the exact-byte HTTP
adapter. It is the counterparty, not a dependency. Do not vendor, fork, or
patch it.

Pinned image: `apache/fineract:1.11.0@sha256:d2da31748f5550b5ebe362b245283b555c71fc914623c29ec1534fe54487f954`.
Upstream: [apache/fineract](https://github.com/apache/fineract) (Apache-2.0).

Review date: **31 December 2026**. On that date this pilot is promoted to a
supported integration with its own claim discipline, or it is removed.

Allocate **6GB** to Docker Desktop. First boot runs Liquibase; several
minutes is normal. `seed.py` waits up to 300s for
`https://localhost:8443/fineract-provider/actuator/health` → `{"status":"UP"}`
(`FINERACT_HEALTH_TIMEOUT_SECONDS` overrides).

## How to run

```bash
cd pilot/fineract
docker compose up -d
python3 seed.py
# from the repo root, after seed-state.json exists:
pytest -m pilot
```

That sequence, twice on the same container, is the demo. Re-run `seed.py`
is safe: clients and accounts are looked up by `externalId`. Recreating the
stack rotates the cert: `docker compose down -v && docker compose up -d`,
then re-seed.

## What the four tests prove

- `test_payload_mutated_after_allow`: after ALLOW of A→B 500, a destination
  mutation to C is refused before `connect()`; Fineract balances are unchanged.
- `test_permit_replay`: A→B 100 executes once; replaying the permit is refused
  at the consume ledger; Fineract shows one transfer from that dispatch.
- `test_budget_exhausted_across_agents`: two agents share a group cap of 1000;
  after 900, a second agent's 200 is refused at the group breaker; Fineract
  total moved is 900.
- `test_chain_verifies_independently`: `tools/verify_records.py` in a
  subprocess with empty `PYTHONPATH` reports clean; this pytest session's
  dispatched `action_digest`s match this session's Fineract transfers.

The destination mutation in case 1 is fault injection by the test.

## What it does not prove

This is an open-source core in a lab, a single instance, no production data,
no Tier-1 deployment. No regulator has reviewed it. `docker compose up`
passing is not a banking integration and not a production claim.

`test_chain_verifies_independently` is a bijection for this pytest session's
`run_id`. It does not prove the ledger contains nothing else.

Pilot tests error (they do not skip) if `seed-state.json` is absent:
`cd pilot/fineract && python3 seed.py`. Assertions are deltas from a snapshot
taken at test start, never absolute balances.

## REMOVAL

This pilot is deletable. When it expires or is abandoned:

```
rm -rf pilot/ tests/pilot/ docs/pilot/
# then revert, in the same commit:
#   docs/WHAT-WE-DO-NOT-CLAIM.md  -> remove the core-banking lab paragraph
#   README.md                    -> drop the tests/pilot/test_fineract_enforcement.py row
# then: pytest  (must pass, unchanged count minus the pilot tests)
```

`usecases.yaml`, a `pilot` extra/marker in `pyproject.toml`, and a `pilot` CI
job were never added. Do not invent them on removal.
