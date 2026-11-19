# 0043: Daily limits per business key are counted on the server

Status:     accepted
Date:       2026-11-19
Pinned by:  tests/test_decide_limits.py::test_server_count_limit_holds;
            tests/test_decide_limits.py::test_server_amount_limit;
            tests/demos/test_live_checkout_limits.py::test_parallel_smurfing_pays_three;
            tests/demos/test_live_checkout_limits.py::test_daily_amount_needs_a_human;
            tests/test_pg_ledgers.py::test_decide_limits_hold_across_instances

## What forced the decision
The refund policy's `velocity-limit` ("at most 3 refunds per customer per
day") reads `customer_refunds_today`, a count the caller's tool computes
before deciding. Probing the live refund demo, five Rs 19,999 refunds for one
customer fired at once each read 0 and were all allowed and paid: Rs 99,995
against a limit of three. Sequentially the limit held, but a customer could
take 3 x Rs 19,999 a day with no human, because nothing capped the total.

## The decision
With `PV_DECIDE_LIMITS` set, the server counts allowed decisions per key per
day and claims each one atomically when a mintable ALLOW is sealed:

    PV_DECIDE_LIMITS='{"POST /v1/refunds": {"key": "customer_id",
        "max_count": 3, "max_amount": 60000, "utc_offset_minutes": 330}}'

The key and amount are read from the sealed `execution_action.parameters`
(like ADR 0041's transaction key); the window is the calendar day at the
configured UTC offset. One conditional UPDATE per decision on the key's row
for the day, so replicas sharing the database agree.

- Over `max_count`: BLOCK (`DAILY_COUNT_LIMIT`). An approval does not lift it.
- Over `max_amount`: BLOCK (`DAILY_AMOUNT_LIMIT`) unless the ALLOW was granted
  by a human approval (`triggered_by: approval`).
- A missing key or amount: BLOCK (`DECIDE_LIMIT_INPUT_MISSING`).
- Released if the decision is not sealed, like ADR 0041 and ADR 0042.

Holding a refund for approval when the day's total would pass the limit is
the policy's job: an approval can only satisfy a REQUIRE_APPROVAL the engine
produced (ADR 0020), so a server-side hold could never be approved. The live
refund demo adds a fact, `customer_amount_today_after`, and a rule,
`daily-amount-limit` (require_approval above Rs 60,000). The server's amount
limit is the backstop for when that fact was stale: a decide that loses the
race is blocked, and decided again it is held for approval.

## What this does not do
- It counts what this server allowed. Refunds made elsewhere (a support desk
  in the payments system) are not seen; that needs facts from the system of
  record.
- It counts allowed decisions, not money moved: an ALLOW whose payment fails
  still counts until the day ends.
- The key is the field the caller's action carries; a caller that names a
  different customer escapes the count. Same limit as ADR 0041's key.
- Opt-in and per operation. Unset, nothing is counted.
