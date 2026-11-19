# 0042: Delegation links carry budgets, argument constraints and a depth limit

Status:     accepted
Date:       2026-11-19
Pinned by:  tests/multi_agent_security/test_delegation_v2.py::test_server_budget_is_cumulative;
            tests/multi_agent_security/test_delegation_v2.py::test_server_sibling_race;
            tests/multi_agent_security/test_delegation_v2.py::test_server_constraints;
            tests/multi_agent_security/test_delegation_v2.py::test_server_max_depth;
            tests/test_pg_ledgers.py::test_delegation_budget_holds_across_instances

## What forced the decision
Probing delegation on `/v1/decide` (operator -> A -> B, rupee refunds) found
three things a `pv-delegation/1` link cannot say:

- `max_amount` caps one action. B made three Rs 3,000 refunds under a link it
  was meant to treat as Rs 5,000 in total, all allowed; A and two siblings
  spending at once took Rs 27,000 from a Rs 10,000 pool.
- A link restricts which capability, not with what values: a refund for
  merchant M-999 passed under a delegation meant only for M-101.
- The only depth bound is a fixed eight links; an operator could not say
  "A may sub-delegate at most twice".

## The decision
A link signed with any of `budget`, `constraints` or `max_depth` is a
`pv-delegation/2` link (exact field set; v1 links are unchanged and still
verify, and `issue_link` without the new arguments still produces v1).

- Narrowing, in `verify_chain`: each limit is null (no limit) or narrows the
  parent's. A child may not raise or drop a budget, must keep every parent
  constraint with a subset of its values, and must lower `max_depth` by at
  least one; a parent at depth 0 may not delegate. A v1 child under a
  limited v2 parent is refused as widening.
- Constraints, in `within_scope`: every link's constraints must hold for the
  action's arguments; a missing argument refuses. Values are strings or
  integers, no wildcards, at most 32 keys and 64 values each.
- Budgets, in `/v1/decide`: when a decision under a chain the engine verified
  in this request is ALLOWED, `DelegationBudgets.charge` charges its amount
  to every budgeted link in one transaction (conditional UPDATE per row,
  minor units). If any would go over, nothing is charged and the decision is
  a BLOCK (`delegation_budget_exceeded`). The charge is released if the
  decision is not sealed (a later control blocked it, or the record failed),
  like the transaction reservation (ADR 0041). The table lives with the
  decision store, SQLite or shared PostgreSQL.

## What this does not do
- A budget counts authority used, not money moved: a sealed ALLOW keeps its
  charge even if no permit is minted or the payment fails.
- Budgets do not reset with time. A new period needs a new link.
- Constraints are equality allow-lists on top-level arguments.
- Budgets are enforced on `/v1/decide`. The library's `authorize` (receiver
  challenge path) checks constraints and depth but keeps no spend ledger.
- Found while testing, not changed: on SQLite, concurrent decides for the
  same agent can fail to seal a record (fails closed; noted in ADR 0041).
