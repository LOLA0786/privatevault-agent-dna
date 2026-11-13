# 0039: Single use is enforced where the money moves

Status:     proposed
Date:       2026-11-12
Pinned by:  tests/receiver/test_receiver_transactions.py::test_second_permit_for_the_same_invoice_is_refused
            (pins the receiver-side control this decision relies on; no test
            pins the open parts listed at the end)

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

## The decision (proposed)
For payments, "at most once" is enforced by the receiving system, in a
ledger the agent side cannot write: the receiver kit, with a business
transaction key (ADR 0030) declared for every payment operation. The
agent-side single-use tables stay as a first line and as evidence; they
are not the guarantee.

What that already gives, today, without new code: the receiver admits a
permit at most once (`receiver_consume`), and a second permit for the same
transaction, such as the same invoice, is refused with 409
`RECEIVER_DUPLICATE_TRANSACTION` whatever the agent side minted. Two
permits minted from one approval after a deleted `approval_consume` row are
two permits for the same transaction, so the second does not execute.

This does not remove the reviewer's payment condition 3 ("only the server
can write to the database, even with signing on"). The agent side still
mints a second permit after a deleted row, and the receiver lets it through
in the cases listed at the end. What it does is state when condition 4
("the receiver keeps its own record of used permits") actually protects a
payment: the permit carries a declared business key, one upgraded receiver
with one ledger handles that operation, and that ledger has not been
restored from an older backup.

## Alternatives and their cost

| Option | What it stops | Cost | State |
|---|---|---|---|
| A. Receiver-side business keys (this decision) | A second execution of the same transaction, whatever was minted | Every payment operation needs a natural key; operations without one are not covered; the receiver kit must be in the payment path | Shipped (ADR 0030) |
| B. Receiver claims the approval and the decision a permit came from | A second execution from one approval or one decision, for every operation, key or not | The signed permit must carry both, and the receiver must claim them: a change to the permit format, the spec and the Rust conformance vectors | Not built; needs an owner decision |
| C. Hash-chain and checkpoint the single-use tables | Shows a deletion after the fact, if a checkpoint was taken and held elsewhere | Does not prevent the double mint when it happens | Not built |
| D. A separate store for single-use state (second database or file the database user cannot reach) | Moves the condition from "the database" to "that store" | Multiple replicas need shared storage with an exclusive claim; condition 3 becomes a condition on that store | Not built |
| E. Sign the single-use rows | Nothing that matters here | A signature cannot show a missing row | Rejected |

## Still open under this decision
- **The agent-side double mint itself.** Nothing here stops it; a second
  permit is still minted after a deleted `execution_authorization_mint`,
  `approval_consume` or `grant_revocations` row, with signing on or off.
- **Revocations stored in the database.** Deleting a `grant_revocations`
  row lets a revoked grant mint again, and the receiver does not know about
  grant revocations. Revoke in `PV_GRANTS_FILE` (remove the grant) as well
  as at runtime; delegation revocations already live in
  `PV_DELEGATION_FILE`.
- **Operations without a business key.** Both permits execute. Only option
  B covers them.
- **More than one receiver ledger.** Two receiver hosts with separate
  ledgers each admit a permit for the same transaction (ADR 0030 covers one
  SQLite file on one receiver host).
- **A restored receiver ledger.** Restoring the receiver's ledger from a
  backup taken before a payment lets a new permit for the same transaction
  through.
- **A receiver not upgraded, or with no keys declared.** Both permits
  execute.
- **Restore.** `PV_MINT_NOT_BEFORE` stops old decisions minting again; a
  consumed approval and a lost revocation still come back.
- **The full N-1 attack has not been run against the receiver kit.** The pin
  above shows the receiver refusing a second permit for the same invoice;
  it does not reproduce the agent-side deletion end to end. The review of
  #230 measured the receiver-restore and two-ledger cases above.
