# 0046: A refused decide gives back its grant spend

Status:     accepted
Date:       2026-11-23
Pinned by:  tests/demos/test_live_checkout_grant_spend.py::test_refused_decides_give_back_the_grant_spend;
            tests/demos/test_challenger.py::test_refused_decides_do_not_spend_the_grant;
            tests/test_grant_spend_release.py;
            tests/test_pg_grants.py::test_release_gives_back_spend_on_any_instance

## What forced the decision
The engine commits a grant's spend as soon as it reaches ALLOW. The API
server then runs controls of its own: the fact check (ADR 0045), the
transaction reservation (ADR 0041), daily limits (ADR 0043) and the chain's
budgets (ADR 0042). Each of those that refuses releases its own claim, but
nothing gave back the grant spend. The continuous challenger's budget oracle
(`demos/live_checkout/challenger.py`) found it: a lie refused with
`FACTS_MISMATCH` charged the refund grant its full amount (Rs 11,600);
twelve challenged actions leaked Rs 2,27,415; and in a three-minute run the
Rs 10,00,000 grant was spent after about forty honest refunds, after which
every refund waited for a human. No money moved, but an agent that lies,
which ADR 0045 is built to stop, could still drain its budget and fill the
approval queue.

## The decision
The server opens `collect_spend()` around the engine. The spend committed
inside it goes to `_seal_decision`, which already releases the reservation,
the chain's budget charge and the limit claim: a verdict that is not ALLOW
gives the spend back before the record is written, and a record that cannot
be written gives it back too. Only a sealed ALLOW keeps it. The release takes
the same lock as the commit (SQLite `BEGIN IMMEDIATE`, PostgreSQL
`SELECT ... FOR UPDATE`), never takes spend below zero and never creates a
row.

## What this does not do
- An ALLOW that is never minted or sent keeps its spend.
- A fault between the engine and the seal (an exception in a later control)
  left the spend charged until ADR 0047 gave it back.
- Until a refused decide reaches the seal, its spend counts against the
  budget, so a concurrent decide can be held for an approval it would not
  need a moment later.
