# Production Hardening — Status & Roadmap

What "production grade" actually requires, broken into named
capabilities, each marked by real status. Written so a bank's
infrastructure or security reviewer gets a precise answer instead of
either silence or overclaim.

**How to read this:** SHIPPED means tested and verifiable today.
SCOPED means designed and estimated, not built. NOT STARTED means
named but no design work has happened. Every SHIPPED claim below
points at the test file that proves it.

---

## Correctness & failure handling

| Capability | Status | Evidence |
|---|---|---|
| Fail-closed on internal fault (engine layer) | **SHIPPED** | `tests/test_fail_closed.py` — any exception in scorer/invariant/authorizer/UAAL produces a deterministic BLOCK, never a crash or silent pass |
| Fail-closed on internal fault (HTTP layer) | **SHIPPED** | `tests/test_api_fail_closed.py` — fault propagates to a 403, not a 500 |
| Restart survival (single process) | **SHIPPED** | `tests/test_restart_survival.py`, `tests/test_api_restart.py` — chain state rebuilds from store, verified intact after kill+restart |
| Precedence-order integrity (can't silently reorder) | **SHIPPED** | `tests/test_precedence_contract.py` — hash-pinned contract, CI-checked against the actual code path on every push |
| Precedence orthogonality (correct winner when multiple levels fire) | **SHIPPED** | `tests/test_precedence_orthogonality.py` |
| Adversarial scenario coverage | **SHIPPED** | `spec/adversarial/attack_corpus.py`, 11/11 passing, built for external extension |
| Evidence-adapter ground-truth isolation | **SHIPPED** | `tests/test_adapter_framework.py` — forbidden-key scanning, dry-run-before-live |

## Concurrency & scale

| Capability | Status | Notes |
|---|---|---|
| Single-writer correctness | **SHIPPED** | All existing tests assume one process; correct in that mode |
| Multi-writer safety (concurrent processes, same store) | **NOT STARTED** | Chain-head read-then-write is not currently atomic across processes. A race between two writers for the same agent could produce a chain fork. Scoped fix: move chain-head lookup into the store's own transaction (SQLite: `BEGIN IMMEDIATE` + read-modify-write in one transaction). Estimated 1 session with tests once a real multi-process requirement exists. |
| Horizontal scaling (multiple app instances) | **NOT STARTED** | Depends on multi-writer safety above. No load balancer story, no shared-nothing design decided yet. |
| Throughput benchmark, single process | **SHIPPED** | `tools/benchmark.py` — stated methodology, rerunnable, no unverified numbers cited |
| Throughput benchmark, concurrent/production load | **NOT STARTED** | Requires multi-writer safety first; a concurrency benchmark on a single-writer system would not be meaningful |

## Persistence & storage

| Capability | Status | Notes |
|---|---|---|
| SQLite/WAL persistence | **SHIPPED** | `agent_dna/sqlite_store.py`, tested restart-safe |
| Store-to-canonical-format export identity | **SHIPPED** | Exported JSONL is byte-identical to what `verify_records.py` consumes — the DB can never become a second source of truth |
| Postgres-interface storage | **SCOPED** | `DecisionStore`/`SQLiteDecisionStore` already share a contract; a `PostgresDecisionStore` implementing the same interface is mechanical. Estimated 1 session once a customer's infra requires it — not built speculatively. |
| Backup/disaster recovery | **NOT STARTED** | No documented backup strategy. For a pilot, this is the customer's own infra responsibility (self-hosted deployment); for managed production, needs a real design. |

## Security

| Capability | Status | Evidence |
|---|---|---|
| API-key authentication | **SHIPPED** | `agent_dna/apikeys.py` — SHA-256 hashed at rest, keys never stored plaintext |
| Ed25519 record signing | **SHIPPED** | `agent_dna/signer.py`, constant-time signature verification |
| Timing-attack-safe HMAC comparison | **SHIPPED** | Found and fixed during consensus-module vendoring; `tests/test_secure_quorum.py` |
| Independent tamper verification | **SHIPPED** | `tools/verify_records.py`, stdlib-only, zero dependency on the producing codebase |
| Secrets management (key rotation, vaulting) | **NOT STARTED** | Signing key and API keys are environment/file-based today. No rotation mechanism, no integration with a secrets manager (Vault, AWS Secrets Manager, etc.). Estimated: real design work, not a quick add — depends on deployment target. |
| Third-party security certification (SOC 2, ISO 27001) | **NOT STARTED** | See `docs/WHAT-WE-DO-NOT-CLAIM.md` — pre-seed, no funded timeline yet. |
| Penetration testing | **NOT STARTED** | No formal external pentest has been performed. Internal adversarial corpus (`spec/adversarial/`) is not a substitute and is not claimed as one. |
| Vulnerability disclosure process | **NOT STARTED** | No `security.txt`, no formal disclosure channel yet. Low effort, should be done regardless of pilot timing. |

## Observability

| Capability | Status | Notes |
|---|---|---|
| Structured audit trail | **SHIPPED** | The decision record chain itself — every decision is a structured, queryable event |
| Application logging (errors, requests) | **NOT STARTED** | No structured logging framework wired in; relies on default framework/stdout logging today. |
| Metrics/monitoring (latency, error rate, throughput) | **NOT STARTED** | No Prometheus/equivalent instrumentation. For a pilot, `tools/benchmark.py` and manual log inspection substitute; not sufficient for ongoing production monitoring. |
| Alerting | **NOT STARTED** | No alerting pipeline. |
| Distributed tracing | **NOT STARTED** | Not relevant at current single-process scale; would matter once horizontally scaled. |

## Deployment

| Capability | Status | Notes |
|---|---|---|
| Docker/compose, single container | **SHIPPED** | `Dockerfile`, `docker-compose.yml`, tested via CI container smoke test |
| CI: full test suite + spec vectors on every push | **SHIPPED** | `.github/workflows/` |
| Kubernetes manifests | **NOT STARTED** | Not built; single-container deployment is the current target. |
| Blue/green or rolling deployment | **NOT STARTED** | N/A at single-instance scale. |
| Air-gapped / fully offline deployment | **PARTIALLY SHIPPED** | The engine itself has no required external network calls; the independent verifier is explicitly stdlib-only and works offline. Full air-gap deployment packaging (offline dependency bundling, etc.) not formally tested. |

---

## What this means for a pilot specifically

A **scoped, single-workflow, single-process pilot** (per
`PILOT-SCOPE.md`) is honestly supportable today: fail-closed,
restart-safe, signed, independently verifiable, with a real security
boundary and a real adversarial test corpus. This is a legitimate,
defensible claim.

A **multi-instance, monitored, horizontally-scaled production
deployment with formal certification** is not supportable today, and
this document exists so that gap is stated plainly rather than
discovered during a bank's infrastructure review.

If a specific pilot's requirements make any NOT STARTED item above a
real blocker, it becomes a scoped, estimated engineering task — not
speculative work done in advance of a named need. This is a
deliberate sequencing choice: building the wrong shape of resilience
before knowing a customer's actual requirements wastes exactly the
kind of time a real pilot's clock does not allow for.
