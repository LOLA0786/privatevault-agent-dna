# 0041: The server reserves a business transaction at decide

Status:     accepted
Date:       2026-11-16
Pinned by:  tests/test_decide_reservation.py::test_second_allow_for_one_transaction_is_blocked;
            tests/test_decide_reservation.py::test_concurrent_decides_allow_at_most_one;
            tests/test_decide_reservation.py::test_lapsed_reservation_allows_a_new_decide;
            tests/test_pg_ledgers.py::test_reservation_has_one_holder_across_instances;
            tests/demos/test_live_checkout.py::test_second_decide_for_one_refund_is_blocked

## What forced the decision
The audit at `03cd1f6` that led to ADR 0040 found two halves of one problem.
A rule such as `duplicate-refund` reads what has already been paid, so two
decides for one refund taken before either is paid both see nothing paid and
both seal an ALLOW. ADR 0040 made the receiver refuse the second permit. The
server still vouched twice for one transaction, and a receiver without a
transaction key, or a second receiver, would have paid twice.

## The decision
With `PV_DECIDE_TRANSACTION_KEYS` set, the server reserves the transaction
when it seals a mintable ALLOW:

    PV_DECIDE_TRANSACTION_KEYS='{"POST /v1/refunds": "refund_id"}'

The mapping is from the sealed dispatch operation to a dotted field of the
sealed `execution_action.parameters`, the same shape as the receiver's
`PV_RECEIVER_TRANSACTION_KEYS`.

- A second mintable decide for the same transaction, while the first holds
  it, is sealed as a BLOCK (`triggered_by: transaction_reservation`,
  `TRANSACTION_RESERVED`) that names the holding decision and when the hold
  lapses. A BLOCK cannot mint.
- An operation that declares a key and an action that carries no usable
  value there (missing, empty, not a string or integer) is a BLOCK
  (`TRANSACTION_KEY_MISSING`).
- The hold lasts `decision_window_seconds` plus a five second clock margin
  from the decide. A permit never outlives the decision window (ADR 0024),
  so once the hold lapses nothing minted from the first decision can run.
- The reservation is claimed before lineage's approval claim and released
  if a later control blocks the decide or its record is not sealed. A sealed
  ALLOW's reservation is never released early.
- The reservation table lives with the decision store: the same SQLite
  file, or the shared PostgreSQL database, so replicas agree.
- Malformed configuration refuses to start. Unset, nothing changes.
- The live refund demo sets it for `POST /v1/refunds`.

## What this does not do
- It is opt-in and per operation. The server does not know which operations
  move money; an undeclared operation is not reserved.
- It is not released when the permit is consumed, refused or expires: the
  server cannot see what the receiver did. An honest retry of a refund whose
  dispatch failed waits for the hold to lapse (five minutes by default),
  which is also what CONTRIBUTING.md asks of an indeterminate dispatch.
- After the hold lapses a new decide is judged on its own. It relies on the
  policy seeing the paid refund by then, and on the receiver's key
  (ADR 0040). It is not exactly-once execution.
- The key is the field the caller's action carries. In the refund demo the
  agent-side tool computes `refund_id`; a compromised tool can choose another.
- Audit-only decides (no `execution_action`) reserve nothing.
- Found while testing, not changed here: on SQLite, concurrent decides for
  one agent in one process can fail to seal a record (the per-agent chain's
  UNIQUE constraint). It fails closed and predates this ADR; a decide that
  fails that way releases its reservation.
