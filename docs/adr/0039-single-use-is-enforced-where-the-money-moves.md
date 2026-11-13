# 0039: Single use is enforced where the money moves

Status:     accepted (proposed 2026-11-12; option B accepted by the owner and
            built 2026-11-13)
Date:       2026-11-13
Pinned by:  tests/receiver/test_receiver_sources.py::test_second_permit_for_the_same_decision_is_refused_and_not_consumed
            tests/receiver/test_receiver_sources.py::test_second_permit_under_the_same_approval_is_refused
            tests/multi_agent_security/test_double_mint_at_the_receiver.py::test_one_approval_used_twice_executes_once
            tests/receiver/test_receiver_transactions.py::test_second_permit_for_the_same_invoice_is_refused

## What forced the decision
External reviews of #227 and #228/#229 (2026-11-11/12), finding N-1: someone
who can write to the agent-side database can delete rows from
`execution_authorization_mint`, `approval_consume` and `grant_revocations`, with
decision signing on or off. One human approval then yields two payment
permits, a decision that already minted mints again, and a revoked grant
mints again. Restoring a genuine older backup has the same effect (N-2).

Signing decision records (ADR 0035, and the mint re-check of #227) does not
help here, and cannot:

- A signature proves what a row says. It cannot prove that a row is
  missing.
- Hash-chaining the rows catches a deletion from the middle, not from the
  end, and the attack deletes the newest row (the consume that just
  happened).
- Catching a deletion from the end needs a head held outside the database
  (a checkpoint). Catching it before a second mint needs that outside party
  consulted on every mint.

No change inside a database can stop someone who can write that database
from rolling its state back. The question is only where "at most once" is
enforced instead.

## The decision
"At most once" for an effect is enforced by the receiving system, in a
ledger the agent side cannot write. The agent-side single-use tables stay
as a first line and as evidence; they are not the guarantee.

The receiver's ledger claims, in the same transaction that admits a permit:

1. the permit itself (`receiver_consume`, unchanged);
2. the decision it was minted from (`decision_receipt_digest`) and, when it
   carries one, the approval (`approval_artifact_digest`), in
   `receiver_sources` (option B, new);
3. a declared business transaction key, where the operation has one
   (ADR 0030, unchanged).

A second, different permit for an admitted decision is refused with 409
`RECEIVER_DUPLICATE_DECISION`; one made under an admitted approval with 409
`RECEIVER_DUPLICATE_APPROVAL`. Neither is consumed. Both digests are signed
fields of every permit (spec execution-v01), so a presenter cannot strip or
change them. The claims are never released: the agent side never mints a
second permit for a decision (ADR 0016) or uses an approval twice
(ADR 0020), so a legitimate flow never needs one released.

The proposal said option B would change the permit format, the spec and
the Rust conformance vectors. That was wrong: the permit already carried
both digests. No format changed.

This does not remove the reviewer's payment condition 3 ("only the server
can write to the database, even with signing on"). The agent side still
mints the second permit; this stops it executing, under the conditions in
the last section.

## Alternatives and their cost

| Option | What it stops | Cost | State |
|---|---|---|---|
| A. Receiver-side business keys | A second execution of the same transaction, whatever was minted | Every covered operation needs a natural key | Shipped (ADR 0030) |
| B. Receiver claims the decision and the approval a permit came from | A second execution from one decision or one approval, for every operation, key or not | One more table in the receiver ledger | Built (this ADR) |
| C. Hash-chain and checkpoint the single-use tables | Shows a deletion after the fact, if a checkpoint was taken and held elsewhere | Does not prevent the double mint when it happens | Not built |
| D. A separate store for agent-side single-use state, out of the database writer's reach | The second mint itself | Multiple replicas need shared storage with an exclusive claim; condition 3 becomes a condition on that store | Not built; needs an owner decision on where the store lives |
| E. Sign the single-use rows | Nothing that matters here | A signature cannot show a missing row | Rejected |

## Still open under this decision
- **The agent-side double mint itself.** A second permit is still minted
  after a deleted `execution_authorization_mint`, `approval_consume` or
  `grant_revocations` row, with signing on or off. It is refused at an
  upgraded receiver; anything that executes without that receiver runs it.
- **Revocations stored in the database.** Deleting a `grant_revocations`
  row lets a revoked grant mint and execute again: the receiver does not
  know about grant revocations. Revoke in `PV_GRANTS_FILE` (remove the
  grant) as well as at runtime; delegation revocations already live in
  `PV_DELEGATION_FILE`.
- **More than one receiver ledger.** Two receiver hosts with separate
  ledgers each admit one permit for the same decision. The ledger is one
  SQLite file on one receiver host.
- **A restored receiver ledger.** Restoring the receiver's ledger from a
  backup taken before a payment forgets the claims made since, and a
  second permit is admitted.
- **A receiver not upgraded.** It does not make these claims.
