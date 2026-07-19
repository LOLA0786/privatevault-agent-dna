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
| Multi-writer safety (concurrent processes, same store) | **SHIPPED** | Atomic chain-head via `append_atomic`/`get_chain_head` in one store transaction; thread-local SQLite connections after a shared-connection cursor race was caught, root-caused, and pinned. `tests/test_multi_writer_safety.py`, `tests/test_connection_thread_safety.py` |
| Horizontal scaling (multiple app instances) | **NOT STARTED** | Multi-writer safety (its prerequisite) is now shipped. No load balancer story, no shared-nothing design decided yet. |
| Throughput benchmark, single process | **SHIPPED** | `tools/benchmark.py` — stated methodology, rerunnable, no unverified numbers cited |
| Throughput benchmark, concurrent/production load | **NOT STARTED** | Prerequisite (multi-writer safety) now shipped; benchmark itself not built |

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

## Connector (agent-harness enforcement)

| Capability | Status | Evidence |
|---|---|---|
| Production composition root (one builder assembles the full stack -- UAAL/consensus/economics always attached (evidence-gated), policy/grants config-gated with honest not_configured manifest, breaker always, GET /v1/runtime serves the manifest; HTTP and MCP consume the same runtime; legacy MCP gateway retired to experimental/) | **SHIPPED** | `tests/test_composition.py`, `tests/test_quarantine.py` |
| Circuit-breaker transactional preflight (projected counters block the crossing action itself; concurrent payments serialize against the same budget; arguments["amount"] reaches the breaker; breaker faults fail closed) | **SHIPPED** | `tests/test_p0_audit.py::test_threshold_crossing_payment_blocked_before_execution`, `::test_arguments_amount_reaches_breaker`, `::test_concurrent_payments_cannot_all_pass_same_budget`, `tests/test_circuit_breaker.py` |
| Strict independent verifier (unique ids, full lineage: parent exists/same-agent/immediate-prior, follows-edge exactly-iff-parent, execution agent binding, exact DRP field sets, strict JSON incl. non-finite rejection, enums, hex formats, anchored agents reported per drp/0.1 anchor rule) | **SHIPPED** | `tests/test_p0_audit.py::test_verifier_rejects_nonexistent_parent`, `::test_verifier_rejects_duplicate_decision_id`, `::test_anchor_verdict_is_consistent_between_verifiers`, `tests/test_decision_store.py`, `tests/test_execution_feedback.py` |
| UAAL evidence tri-state (ABSENT skips honestly, MALFORMED amounts fail closed, INCOMPLETE enterprise_state skips -- garbage or empty evidence can never satisfy an invariant) | **SHIPPED** | `tests/test_p0_audit.py::test_malformed_amount_fails_closed`, `::test_empty_enterprise_state_is_not_verified_state`, `tests/test_uaal_layer.py` |
| Consensus vote integrity (pv-vote/1: one vote per voter per action, signature bound to action/vote/nonce/expiry, replay and duplicate rejection) | **SHIPPED** | `tests/test_secure_quorum.py`, `tests/test_p0_audit.py::test_one_voter_cannot_vote_twice`, `::test_vote_cannot_replay_across_actions` |
| OPA fail-closed (unreachable/empty/malformed policy backend raises; engine converts to BLOCK/engine_fault -- never a fabricated policy verdict, never silent ALLOW) | **SHIPPED** | `tests/test_p0_audit.py::test_opa_unavailable_engine_blocks`, `::test_opa_unavailable_adapter_contract`, `::test_opa_empty_result_is_not_allow` |
| API identity binding (credential is authoritative for agent_id; cross-agent decide/outcome/query rejected) | **SHIPPED** | `tests/test_p0_audit.py::test_key_cannot_decide_as_another_agent`, `::test_key_cannot_report_outcome_for_another_agent` |
| Single enforcement path, identity fail-closed | **SHIPPED** | `tests/connector/test_middleware.py` — no/invalid/audit-scoped key -> BLOCK; audit keys proven unable to exercise enforcement |
| MCP transport-level enforcement | **SHIPPED** | `tests/connector/test_mcp_adapter.py` — real client/server, allowed call executes, suspended agent refused with signed hash in-band |
| Per-session HTTP identity | **SHIPPED** | `tests/connector/test_mcp_http_identity.py` — real streamable HTTP, sessions on one server are distinct agents |
| Multi-agent isolation under concurrency | **SHIPPED** | `tests/connector/test_multi_agent_isolation.py` — found and forced the fix of a real middleware bug under multi_writer_safe recorders |
| Group (swarm) circuit breaker | **SHIPPED** | `tests/test_group_breaker.py` — distributed drain across declared groups, group-atomic gated reset |
| Cross-agent invariants at the transport | **SHIPPED** | `tests/connector/test_cross_agent.py` — escalation-only, declared execution windows |
| No-mocks-on-enforcement-path CI guard | **SHIPPED** | `tests/connector/test_standard_no_mocks.py` (docs/ENGINEERING-STANDARD.md rule 1) |
| Private SDK surface pins | **DECLARED** | `FastMCP._tool_manager`, `mcp.shared._httpx_utils` — mcp>=1.0, integration tests fail loudly on surface change |
| TLS termination | **NOT STARTED** | Deployment responsibility; bearer keys require TLS in front of the connector |
| Framework adapters beyond MCP (OpenAI SDK, LangGraph, CrewAI) | **SCOPED** | Same middleware, thin per-framework translation (~40-line adapters); built when a pilot names one |

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

## Rust runtime (pv_runtime)

Scope honesty: the Rust crate is the sealed-record hot core (hash /
seal / chain / sign / verify). It is NOT an enforcement engine port --
the precedence engine, stores, breakers, and connectors remain
Python-only. Every row below traces to a named test.

| Property | Status | Evidence |
|---|---|---|
| Byte-identical hashing with Python (canonical JSON: sorted keys, compact, ensure_ascii, CPython float repr) | **SHIPPED** | `tools/rust_parity_check.py` (adversarial unicode + float vectors incl. 1e17 / 1e-05 / astral-plane), `rust/tests/canonical_parity.rs` |
| DRP spec-vector conformance (Rust verifies the exact files `tools/verify_records.py` consumes; per-line verdict identical to Python) | **SHIPPED** | `tests/test_rust_conformance.py` |
| Fail-closed sealing (no panics on the seal path; non-finite floats refuse to seal in BOTH languages) | **SHIPPED** | `rust/tests/canonical_parity.rs::nan_drift_score_fails_closed`, `tests/test_nonfinite_guard.py`; `#![deny(clippy::unwrap_used/expect_used/panic)]` makes regressions a compile error |
| Strict edges parsing (invalid JSON errors; two different stored strings can never hash identically) | **SHIPPED** | `rust/tests/canonical_parity.rs::execution_event_invalid_edges_is_error_over_ffi` |
| Ed25519 signer parity (deterministic RFC 8032: Rust and PyNaCl signatures byte-identical, cross-verifying; `PV_USE_RUST_SIGNER=1` path tested) | **SHIPPED** | `tests/test_rust_signer_parity.py` |
| Signing-key hygiene (seed in `Zeroizing` memory both paths; dalek `zeroize` feature on; no seed retained Python-side) | **SHIPPED** | `rust/src/signer.rs`, `agent_dna/signer_bridge.py` |
| Supply-chain gate (RustSec audit; license/source/wildcard policy) | **SHIPPED** | `.github/workflows/rust.yml` `rust-supply-chain` job, `rust/deny.toml` |
| Rust-side persistence / multi-writer safety / anchors | **NOT STARTED** | Python-only (`agent_dna/sqlite_store.py`, `tests/test_multi_writer_safety.py`). The Rust recorder is in-memory; do not claim otherwise. |
| Rust-side chain verification / graph queries (verify_all, lineage) | **NOT STARTED** | Python-only. Rust `DecisionGraph` validates seal + parent on add; it is not the audit verifier. |
