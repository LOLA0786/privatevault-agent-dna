# 0049: Single use across more than one receiver host

Status:     proposed (2026-11-26). The owner chooses; option A is recommended.
Date:       2026-11-26
Pinned by:  no test yet. The accepted option ships with the two-host race
            test described under "Proof", beside
            tests/multi_instance/test_two_processes.py.

## What forced the decision
ADR 0039 put "at most once" in the receiver's own ledger. That ledger is one
SQLite file, and one transaction (`BEGIN IMMEDIATE`) does four things. It
claims the permit (`receiver_consume`), the decision and approval the permit
was minted under (`receiver_sources`) and the business key, such as an
invoice (`receiver_transactions`, ADR 0040), and it appends the next receipt
to the hash chain (`receiver_receipts`). The module says what it does not
do: multi-host deployments need a store with the same exclusive-claim
guarantee, and it does not claim one.

A bank will not run its payment edge on one host, and two receiver hosts
with two SQLite files admit one permit twice, once on each.

The permit is the easy part: it expires within 300 seconds. The other three
claims are the hard part. "One payment per invoice" and "one execution per
approval" are facts about the whole bank, not about a host, so every host
must consult one source of truth inside the transaction that admits.

## Options

### A. One shared PostgreSQL ledger (recommended)
Every host admits in one PostgreSQL transaction: the four claims as
`INSERT … ON CONFLICT DO NOTHING` on today's keys, and the receipt appended
under a lock on a one-row chain head (`SELECT … FOR UPDATE`), so sequence
and linkage cannot fork. SQLite stays the store for a single host.

- It holds for any number of active hosts, with today's semantics, receipts
  and verifier (`tools/verify_receiver_receipts.py`).
- It uses patterns the repository already runs on PostgreSQL 16 (decide
  reservations, the budget ledger, the circuit breaker) and the two-process
  harness of `tests/multi_instance/test_two_processes.py`.
- Its costs are listed below. The replication requirement is the one that
  matters.

### B. Permits bound to one receiver host
Each permit names the one host that may admit it, other hosts refuse it, and
each host keeps its own SQLite file.

Rejected: it makes the permit single-use and nothing else. If the agent side
mints twice for one decision, approval or invoice (the attack 0039 assumes),
the two permits can be bound to two hosts and both admitted, which is what
0039 exists to refuse. It also couples minting to routing, and a load
balancer that terminates TLS with one certificate for every host defeats
the binding.

### C. One active host, with a standby fenced on takeover
One host admits. On takeover the standby refuses every permit issued before
it took over, so nothing the failed host admitted can be replayed.

Rejected as a separate design. Fencing covers permits, not the other three
claims: if the standby's copy lags, an approval or invoice the failed host
admitted can be admitted again under a fresh permit. Making the copy safe
means replicating each claim before the admission completes, which is
option A with one active host, a deployment A supports as it stands.

### D. Route by key at the load balancer
Rejected. One admission carries several keys (permit, decision, approval,
invoice) that hash to different hosts, and failover moves keys between
hosts, which needs C's fencing and inherits its gap.

## What option A costs us
- **The money edge depends on the database.** When PostgreSQL is
  unreachable, every host refuses (fail closed) and payments stop. A bank
  deploying this already runs highly available databases; the receiver's
  becomes one of them.
- **Replication must be synchronous.** With asynchronous replication, a
  failover can lose the newest committed claims, and an approval or invoice
  admitted just before it can then be admitted again. The receiver ledger's
  database needs a synchronous standby, and `tools/verify_deployment.py`
  should refuse a multi-host receiver configuration that lacks one.
- **One chain head serializes every admission.** Throughput is bounded by
  one row lock. It must be measured against the bank's peak before
  production, with per-host chains joined by a signed checkpoint as the
  fallback (see "What would make us revisit").
- **A refusal with no database has no receipt.** The receipt chain lives in
  the database, so a refusal while it is down reaches the caller but is not
  in the chain.
- **Existing single-host claims are not migrated.** A multi-host deployment
  starts with an empty shared ledger. Moving a live SQLite ledger needs an
  import tool, written only if a customer needs one.

## Proof the accepted option ships with
Two receiver processes on one PostgreSQL database, using the harness of
`tests/multi_instance/test_two_processes.py`, with requests split between
them as a load balancer would split them:

1. The same permit sent to both hosts at once is admitted exactly once.
2. Two permits for one decision, and two under one approval, are admitted
   once.
3. Two permits for one invoice are admitted once.
4. The receipts from both hosts form one chain with no fork or gap, and
   `tools/verify_receiver_receipts.py` verifies it.
5. With the database taken away, both hosts refuse and nothing is admitted.
6. A host killed mid-admission leaves the claims and the receipt either all
   present or all absent.

## What would make us revisit
- A measured admission rate below the bank's peak with one chain head: then
  per-host chains joined by a signed checkpoint.
- A bank that needs active-active receivers across regions, where
  synchronous replication costs too much latency: then per-region ledgers,
  with each business key owned by one region.
