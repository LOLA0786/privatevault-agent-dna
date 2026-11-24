# 0047: A fault before the seal gives back every claim

Status:     accepted
Date:       2026-11-24
Pinned by:  tests/test_decide_fault_releases_claims.py::test_fault_before_the_seal_releases_the_reservation;
            tests/test_decide_fault_releases_claims.py::test_release_claims_gives_back_grant_spend

## What forced the decision
ADR 0046 gave back a refused decide's grant spend, and named what it did not
cover: a decide that raised between the engine and the seal kept everything
claimed so far. The grant spend, the transaction reservation (ADR 0041), the
daily limit claim (ADR 0043) and the chain's budget charge (ADR 0042) stayed
held, so one fault in a store could block the honest retry of a refund until
its reservation lapsed, and count against a customer's daily limit for the
rest of the day.

## The decision
The decide handler claims nothing outside a guard. Every claim from the engine
call to the seal is held in one place, and `_release_claims` gives back
whatever was claimed if anything raises before the seal; the exception still
propagates, so the decide fails closed with no record and no permit.
`_seal_decision` uses the same function for a refused verdict and for a
record that cannot be written, so there is one release path, not three.

## What this does not do
- A claim a store made but could not report back before it raised (a
  partial write inside the store itself) is that store's to roll back.
- An ALLOW that is sealed but never sent keeps its claims (ADR 0046).
