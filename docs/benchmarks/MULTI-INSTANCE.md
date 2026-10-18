# Multi-instance: two API processes on one PostgreSQL

What was run, on what, and what it does and does not show.

## Correctness under failure (CI, every commit)

`tests/multi_instance/test_two_processes.py` starts two real `uvicorn`
processes (separate memory, separate connection pools) on a fresh
PostgreSQL 16 database and sends requests round-robin across them, as a
load balancer would. `tests/multi_instance/cluster.py` is the harness.

| Scenario | Result checked |
|---|---|
| 40 concurrent decides of 5 against a budget of 100 | exactly 20 allowed, spent = 100, losers get the ordinary budget refusal, chains verify from the store |
| 10 concurrent `/v1/authorize` of one decision on both processes | one permit, one mint row |
| maker initiates on process A, approves on process B | blocked (maker==checker); a different checker is allowed once; a second approval is blocked |
| SIGKILL one process during 300 concurrent decides | spent never exceeds the budget; every allow the client saw is recorded and paid for; the restarted process allows exactly what is left; chains verify |
| database refuses connections | every request fails with 5xx within the connection timeout, never a verdict; `/ready` returns 503; after the database returns, broken connections fail once and are replaced, then requests are decided again |
| outcome reported on process B for a decision made on process A | accepted; lineage and records read from the store |

A request in flight on a killed process can have its spend committed
without its answer reaching the client (one run: 100 spent, 95 allows
seen). That errs closed: budget can be lost, never exceeded.

## Latency and throughput (sandbox, not production hardware)

`python -m tests.multi_instance.cluster --database-url postgresql://... --instances 2 --requests 1000 --concurrency 8`

Environment: one 2-vCPU VM (Intel Xeon 2.1 GHz) running the load
generator, both API processes and PostgreSQL 16.15 together. Requests are
`/v1/decide` for budgeted payments spread over 32 agents, each with its own
grant; every decision is signed, hash-chained, lineage-recorded and
breaker-checked. 1000 requests per row after a warm-up.

| Instances | Concurrency | Throughput (req/s) | p50 (ms) | p95 (ms) | p99 (ms) |
|---|---|---|---|---|---|
| 1 | 1 | 108 | 8.8 | 11.9 | 15.2 |
| 1 | 8 | 175 | 43.0 | 65.1 | 73.1 |
| 1 | 32 | 144 | 218.2 | 318.5 | 405.5 |
| 2 | 1 | 105 | 8.9 | 12.5 | 18.0 |
| 2 | 8 | 200 | 39.2 | 56.6 | 69.0 |
| 2 | 32 | 177 | 166.8 | 287.0 | 335.9 |

All 6000 requests were decided (no errors). The machine is CPU-bound at
concurrency 8 and above, so these rows measure this VM, not how the
system scales: a second instance on the same two cores adds little. One
agent's own decisions are serial by design (one hash chain, one budget per
grant), so per-agent throughput is bounded by single-request latency.

## Not shown

- Scaling on separate hosts, or any production-sized load.
- Long runs (soak), memory growth over hours, PostgreSQL failover.
- Audit reads at scale: with PostgreSQL, `/v1/verify`, `/v1/records`,
  `/v1/blocked`, `/v1/divergent`, `/v1/lineage` and `/v1/outcome` load
  the ledger from the store on each call (correct across instances, cost
  grows with ledger size), and each process loads it once at start-up.
