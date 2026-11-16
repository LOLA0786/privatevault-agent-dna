# 0040: A receiver names its business key, or says it has none

Status:     accepted
Date:       2026-11-16
Pinned by:  tests/network/test_receiver_hardened.py::test_transaction_key_is_required;
            tests/network/test_receiver_hardened.py::test_transaction_key_settings_are_checked;
            tests/demos/test_live_checkout.py::test_two_decisions_for_one_refund_pay_once

## What forced the decision
An audit at commit `03cd1f6` ran the live refund demo as shipped and paid one
refund twice. Two decides for the same refund, taken before either was paid,
both returned ALLOW: the `duplicate-refund` rule reads what the payments API
has paid, and nothing had been paid yet. Two sealed decisions minted two
distinct permits over byte-identical bodies with the same `refund_id`, and the
receiver gate admitted both. Every single-use guarantee held (one permit per
decision, one use per permit, ADR 0016 and ADR 0039), and the money still
moved twice.

ADR 0030 already closes this: a receiver that declares a transaction key
admits each value once. But the key was optional, the demo did not set it, and
the start-up summary mentioned its absence in passing. With
`PV_RECEIVER_TRANSACTION_KEYS={"POST /v1/refunds": "refund_id"}` the same
audit run paid the refund once and refused the second permit with 409
`RECEIVER_DUPLICATE_TRANSACTION`.

## The decision
The receiver kit treats a missing business key like plaintext or a missing
revocation list (ADR 0027): the gate does not start.

- `PV_RECEIVER_TRANSACTION_KEYS` is required and must name at least one
  operation.
- `PV_RECEIVER_ALLOW_NO_TRANSACTION_KEY=1` starts the gate with none, for a
  local demo or an upstream that deduplicates itself. The start-up summary
  says what that costs. A key together with the flag is a contradiction and
  the gate does not start.
- The live refund demo declares `refund_id` for `POST /v1/refunds`. The
  treasury demo and the kit's compose file set the flag explicitly; their
  behaviour is unchanged and now stated.

## What this does not do
- It does not check that every protected write operation has a key. The kit
  does not enumerate protected operations (everything not listed as
  unprotected is protected), so the check is "at least one key, or the flag".
- The key is only as good as the field named. In the refund demo `refund_id`
  is computed by the agent-side tool, so a compromised tool can write a
  different one. Deriving the key and the policy facts from the system of
  record is separate work.
- The decide-time race itself remains: two ALLOWs are still sealed for one
  refund. The receiver refuses the second; the server does not yet reserve.
- With a key declared, a replay of a paid transaction is refused as
  `RECEIVER_DUPLICATE_TRANSACTION` rather than `RECEIVER_PERMIT_CONSUMED`.
  Both are 409 and nothing is paid; the ledger's claim order is unchanged.
- Library users who construct `ReceiverGate` directly are not affected; the
  constructor's `transaction_keys` argument is still optional.
- It is not exactly-once execution (ADR 0030, "What we do not claim").
