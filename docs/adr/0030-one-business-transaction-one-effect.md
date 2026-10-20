# 0030: The receiver admits each business transaction once

Status:     accepted
Date:       2026-10-21
Pinned by:  tests/receiver/test_receiver_transactions.py::test_second_permit_for_the_same_invoice_is_refused;
            tests/receiver/test_receiver_transactions.py::test_concurrent_permits_admit_one;
            tests/receiver/test_receiver_transactions.py::test_uncertain_answers_block_until_reconciled;
            tests/receiver/test_receiver_transactions.py::test_crash_before_the_answer_keeps_the_key_blocked;
            tests/receiver/test_receiver_transactions.py::test_proxy_records_the_upstream_answer

## What forced the decision
The follow-up review (20 October 2026, item 2) noted that a permit is
single-use but a business transaction is not protected: a new decision for
the same invoice mints a new permit, and the receiver admits each permit
once, so the invoice can be paid twice. A single-use permit is not
exactly-once execution.

## The decision
- The receiver operator declares, per write operation, the field in the
  request body that identifies the business transaction:
  `ReceiverGate(transaction_keys={"POST /api/v1/transfers": "invoice_id"})`,
  or `PV_RECEIVER_TRANSACTION_KEYS` in the receiver kit. The declaration
  is the receiver's, not PrivateVault's: a compromised or misconfigured
  issuer cannot remove it.
- The gate reads the key from the bytes the permit binds (a dotted path in
  the JSON body; a trimmed printable string up to 256 characters, or an
  integer). A missing or unusable key is refused
  (`RECEIVER_TRANSACTION_KEY_INVALID`, 400) without consuming the permit.
- The key `(organisation, operation, key)` is claimed in the same SQLite
  transaction as the permit and the receipt. A key already held refuses
  the request (`RECEIVER_DUPLICATE_TRANSACTION`, 409, signed receipt)
  without consuming its permit, whichever decision or agent minted it.
- The upstream's answer settles the claim (`ReceiverGateProxy` and
  `ReceiverGateMiddleware` record it):
  - 2xx: `EXECUTED`; the key stays refused.
  - 400, 401, 403, 404, 405, 415, 422: `NOT_EXECUTED`; the key is free
    for a new permit.
  - anything else (5xx, 408, 409, 425, 429, 3xx), an exception or no
    answer: `INDETERMINATE`; refused until reconciled.
  - A crash between admission and the answer leaves `CLAIMED`, which
    also refuses.
- `tools/receiver_transactions.py` lists open claims (exit 1 when any are
  open, for monitoring), shows a key's history, and records an operator's
  reconciliation against the system of record (`executed` or
  `not-executed`, with who and why). Every state change is appended to
  `receiver_transaction_events`.
- `ReceiverGateProxy(idempotency_header="Idempotency-Key")` (kit:
  `PV_RECEIVER_IDEMPOTENCY_HEADER`) also sends an opaque reference for the
  transaction upstream, replacing any the client sent, so a system of
  record that deduplicates gets one stable key per transaction.

## What this costs us
- An uncertain answer blocks the invoice until someone checks the system
  of record. That is the intended direction: a wrong "not executed" can
  pay twice, a wrong "blocked" only delays.
- The key is only as good as the field the operator names. An agent can
  put a different value in that field (`INV-1001-b`); the receiver then
  sees a different transaction. Name a field the system of record itself
  validates (its invoice number), not one the caller invents.
- Claims, outcomes and reconciliations are stored in the receiver ledger,
  not in the signed receipt chain; a reconciliation is attributed by the
  name the operator typed. The duplicate refusal itself is a signed
  receipt.
- Like the permit claim, this is one SQLite file: one receiver host.

## What would make us revisit
A shared receiver ledger across hosts (the claim must move with it),
reconciliation driven by the system of record's own API instead of an
operator, or signing outcome and reconciliation events into the receipt
chain.
