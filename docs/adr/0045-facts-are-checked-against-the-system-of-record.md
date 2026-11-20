# 0045: Decision facts are checked against the system of record

Status:     accepted
Date:       2026-11-20
Pinned by:  tests/demos/test_live_checkout_facts.py::test_refund_during_approval_wait_is_caught;
            tests/demos/test_live_checkout_facts.py::test_false_facts_are_refused;
            tests/demos/test_live_checkout_facts.py::test_unreadable_source_refuses;
            tests/test_fact_sources.py

## What forced the decision
Policy rules decide on facts the caller's tool computes and sends in the
arguments (`prior_refunds_for_order`, `customer_refunds_today`, ...). Probing
the live refund demo found three consequences:

- A refund made directly in the payments system while a Rs 25,000 approval
  waited was not seen: the approved decide reused the facts read before the
  wait, and the order was refunded Rs 30,000.
- Daily limits (ADR 0043) counted only what PrivateVault itself allowed.
- A compromised tool can state "no prior refunds" or another customer.

## The decision
With `PV_FACT_SOURCES` set, a decide that would ALLOW or hold for approval
reads the order from the system of record (`refund-facts/1`:
`GET {url}/v1/orders/{order_id}/refund-facts`), derives what each declared
fact must be for this amount and payee, and is a BLOCK if a stated fact
differs, is missing, or has another type (`FACTS_MISMATCH`), if the order is
unknown (`FACTS_ORDER_UNKNOWN`), or if the source cannot be read in time
(`FACTS_UNAVAILABLE`).

Facts are verified, not rewritten: approvals and permits are bound to the
exact arguments (the server already requires `execution_action.parameters`
to equal them), so rewriting would break that binding. A decide on stale
facts is refused and decided again with fresh ones. The check runs before the
reservation, limits and budgets, so nothing is held on stale facts. A
post-approval decide re-reads the source, which catches a refund made during
the wait.

The live refund demo checks every refund fact against its mock payments API,
which serves `refund-facts/1` from the order records and every refund it has
paid, however it arrived, using the same arithmetic as the agent's tool.

## What this does not do
- It trusts the source. A source that lies, or lags, is believed.
- A fact can change between this read and the payment. A second payment for
  the same refund is stopped by the receiver's transaction key (ADR 0040) and
  the reservation (ADR 0041); a refund made elsewhere in that window is not.
- One kind, `refund-facts/1`. Other operations need their own contract.
- Audit-only decides (no `execution_action`) are not checked.
- It adds a read of the system of record to each such decide; when the
  source is down, those decides are refused.
