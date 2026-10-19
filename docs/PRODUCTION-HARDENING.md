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
| Adversarial scenario coverage | **SHIPPED** | `spec/adversarial/attack_corpus.py`, exercised by `tools/run_adversarial.py`, built for external extension |
| Cross-agent loop discovery | **SHIPPED** | Strict, bounded, model-free authority/replay/causal analysis with witness paths and deterministic report digests; `tests/test_loop_discovery.py`, `docs/LOOP-DISCOVERY.md` |
| Offline Discovery Loop | **SHIPPED** | Proposal-only mining, additive history/adversarial replay, divergence budgets, stable security-loop probe, hash-sealed reports, and stdlib verifier; `tests/test_discovery.py`, `docs/DISCOVERY-LOOP.md` |
| Evidence-adapter ground-truth isolation | **SHIPPED** | `tests/test_adapter_framework.py` — forbidden-key scanning, dry-run-before-live |

## Concurrency & scale

| Capability | Status | Notes |
|---|---|---|
| Single-writer correctness | **SHIPPED** | All existing tests assume one process; correct in that mode |
| Multi-writer safety (concurrent processes, same store) | **SHIPPED** | Atomic chain-head via `append_atomic`/`get_chain_head` in one store transaction; thread-local SQLite connections after a shared-connection cursor race was caught, root-caused, and pinned. `tests/test_multi_writer_safety.py`, `tests/test_connection_thread_safety.py` |
| Multiple app instances on one PostgreSQL (correctness) | **SHIPPED** | Budgets, one permit per decision, self-approval, a killed instance and a database outage across two processes: `tests/multi_instance/test_two_processes.py`; Helm chart runs two replicas (`deploy/helm/privatevault`) |
| Horizontal scaling (performance across hosts) | **NOT MEASURED** | No multi-host run, soak test or failover test. Routine reads rebuild the full ledger per call in multi-writer mode (external review finding 4) |
| Throughput benchmark, single process | **SHIPPED** | `tools/benchmark.py` — stated methodology, rerunnable, no unverified numbers cited |
| Throughput benchmark, concurrent load | **PARTIAL** | Two instances on one 2-vCPU VM: `docs/benchmarks/MULTI-INSTANCE.md`. No production-scale or large-ledger figures |

## Persistence & storage

| Capability | Status | Notes |
|---|---|---|
| SQLite/WAL persistence | **SHIPPED** | `agent_dna/sqlite_store.py`, tested restart-safe |
| Store-to-canonical-format export identity | **SHIPPED** | Exported JSONL is byte-identical to what `verify_records.py` consumes — the DB can never become a second source of truth |
| PostgreSQL storage (`PV_DATABASE_URL`) | **SHIPPED** | Every ledger: `tests/test_pg_store.py`, `tests/test_pg_grants.py`, `tests/test_pg_ledgers.py`, `tests/test_pg_shared_state.py`. The receiver kit's ledger is still SQLite only |
| Backup and verified restore | **SHIPPED** | `agent_dna/backup.py`, runbook `docs/operations/BACKUP.md`, `tests/test_backup.py`. Point-in-time recovery and scheduling are the database platform's |

## Security

| Capability | Status | Evidence |
|---|---|---|
| API-key authentication | **SHIPPED** | `agent_dna/apikeys.py` — SHA-256 hashed at rest, keys never stored plaintext |
| Ed25519 record signing | **SHIPPED** | `agent_dna/signer.py`, constant-time signature verification |
| Timing-attack-safe HMAC comparison | **SHIPPED** | Found and fixed during consensus-module vendoring; `tests/test_secure_quorum.py` |
| Independent tamper verification | **SHIPPED** | `tools/verify_records.py`: standard-library chain verification plus optional trusted Ed25519 verification with PyNaCl; neither mode imports the producing runtime |
| Signing keys in a KMS | **SHIPPED** | AWS KMS and Google Cloud KMS (ADR 0023): `tests/test_key_custody.py`, `tests/test_authorize_kms.py`. Not run against a live KMS from inside a cluster |
| Key rotation, secrets-manager integration | **NOT STARTED** | API keys and local seeds are file or environment based; no rotation mechanism |
| Capability-to-operation binding | **SHIPPED** | ADR 0025: operator-declared operations per capability (`PV_OPERATIONS_FILE`); undeclared requests are a sealed BLOCK at decide and refused at mint; required to mint under the secure profile. `tests/test_operation_registry.py` |
| Authority freshness at mint | **SHIPPED** | ADR 0024: mint refused after the approval, grant or decision window ends; permit expiry capped at the earliest. `tests/test_authority_freshness.py` |
| Permit evidence from the server, not the caller | **SHIPPED** | ADR 0026: the policy bundle and grant are sealed at decide and signed into the permit; differing caller values and configuration changes between decide and mint are refused under the secure profile. `tests/test_permit_evidence.py` |
| Third-party security certification (SOC 2, ISO 27001) | **NOT STARTED** | See `docs/WHAT-WE-DO-NOT-CLAIM.md` — pre-seed, no funded timeline yet. |
| Penetration testing | **NOT STARTED** | No formal external pentest has been performed. Internal adversarial corpus (`spec/adversarial/`) is not a substitute and is not claimed as one. |
| Vulnerability disclosure process | **SHIPPED** | `.well-known/security.txt`; contact in `SECURITY.md`. |

## Connector (agent-harness enforcement)

| Capability | Status | Evidence |
|---|---|---|
| Policy mining (`pv policy suggest`: derives candidate controls from sealed history -- thresholds the org already enforces by hand, capabilities refused only by the learned layer, missing standing grants; every suggestion traced to record hashes, emitted gate-ready with assertions derived from observed data, never auto-applied; patterns the schema cannot express are reported as advisories, not fake rules) | **SHIPPED** | `tests/test_policy_miner.py` |\n| Policy change gate (`pv policy check`: rule assertions + counterfactual replay against a committed fixture corpus or sealed history, explicit divergence budgets, CI exit-code contract 0/1/2 -- a control change becomes a reviewable pull request) | **SHIPPED** | `tests/test_policy_gate.py` |
| Shadow policy mode (candidate policies evaluated against the LIVE decision stream, enforcing nothing; divergence report in the bank's own terms; own hash-chained tamper-evident log; a candidate fault cannot touch the enforcement path) | **SHIPPED** | `tests/test_shadow_mode.py` |
| OPA connector hardening (bundle fallback fail-closed -- a degraded bundle cannot authorize by silence; ONE total deadline across retries, bounded p99; rule identity surfaced into DecisionRecord.policy_id; caching opt-in, bounded, never caches denials or degraded results; mTLS/CA/bearer-token transport for in-VPC deployment) | **SHIPPED** | `tests/test_opa_hardening.py`, `tests/test_p0_audit.py::test_opa_unavailable_engine_blocks` |
| Policy as a formal precedence level (contract v4.0: order 2 between invariant and consensus, data-driven block/require_approval, fired rule id written into DecisionRecord.policy_id; structural guard now fails on ANY undeclared level in the engine, both directions) | **SHIPPED** | `tests/test_precedence_contract.py::test_no_undeclared_levels_in_engine`, `tests/test_policy_lineage.py` |
| One grant model (GrantRegistry canonical: expiry/revocation/budget; grant_id written into DecisionRecord.approval_ref; budget spend wired at the verdict seam, fail-closed on ledger faults; malformed amounts fail authorization closed; CapabilityRegistry / AuthorizationPolicy / GrantAuthorizationPolicy deprecated with warnings) | **SHIPPED** | `tests/test_grant_lineage.py`, `tests/test_capability_grants.py` |
| Transactional audit persistence (record + signature envelope committed in ONE store transaction, single- and multi-writer; envelopes survive restart and serve /v1/envelope; UNIQUE(decision_ref) enforces one execution per decision across processes; append_atomic retries ONLY genuine chain races -- duplicate ids surface as errors; multi-writer outcomes resolve via the store, not the unpopulated graph) | **SHIPPED** | `tests/test_transactional_persistence.py`, `tests/test_multi_writer_safety.py`, `tests/test_restart_survival.py` |
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
| Private SDK surface bounds | **DECLARED** | `MCPServer._tool_manager` — mcp>=2.2,<3, locked to 2.2.0; integration tests cover legacy and modern protocol modes |
| TLS termination | **NOT STARTED** | Deployment responsibility; bearer keys require TLS in front of the connector. Receiver-side mTLS for presenters is shipped (ADR 0022) but not the receiver kit's default |
| Framework adapters beyond MCP (OpenAI SDK, LangGraph, CrewAI) | **SCOPED** | Same middleware, thin per-framework translation (~40-line adapters); built when a pilot names one |

## Observability

| Capability | Status | Notes |
|---|---|---|
| Structured audit trail | **SHIPPED** | The decision record chain itself — every decision is a structured, queryable event |
| Application logging (errors, requests) | **PARTIALLY SHIPPED** | JSON logger wired at API startup (`agent_dna/observability/logger.py`); request-level access logs still framework default. |
| Metrics/monitoring (latency, error rate, throughput) | **SHIPPED** | Prometheus counters/histogram on the decide path (`pv_decisions_total`, `pv_blocks_total`, `pv_decide_latency_seconds`, `pv_ready`); `GET /metrics`, `GET /ready`, `GET /v1/ops/summary`. Evidence: `tests/test_platform_ops.py`, `tests/test_metrics_endpoint.py`. Compose profile: `docker-compose.platform.yml`. |
| Readiness probe | **SHIPPED** | `GET /ready` pings the store (SQLite or PostgreSQL); Docker, compose and the Helm chart use it. `tests/test_platform_ops.py`. |
| Vulnerability disclosure packaging | **SHIPPED** | `.well-known/security.txt` + `SECURITY.md` contact. |
| Alerting | **NOT STARTED** | No alerting pipeline. |
| Distributed tracing | **NOT STARTED** | Matters now that several instances can serve one deployment. |

## Deployment

| Capability | Status | Notes |
|---|---|---|
| Docker/compose, single container | **SHIPPED** | `Dockerfile`, `docker-compose.yml`, tested via CI container smoke test |
| CI: full test suite + spec vectors on every push | **SHIPPED** | `.github/workflows/` |
| Kubernetes (Helm chart) | **SHIPPED** | `deploy/helm/privatevault`; CI renders it, validates it against the Kubernetes schemas, checks that unsafe values are refused, installs it on kind with PostgreSQL and runs `tools/verify_deployment.py` (`deploy/helm/privatevault/ci/kind-e2e.sh`). Not run on a managed cluster |
| Rolling deployment | **SHIPPED (chart)** | The chart rolls API pods with no unavailable replica on PostgreSQL; untested under production traffic |
| Air-gapped / fully offline deployment | **PARTIALLY SHIPPED** | The engine and chain-only verifier require no network calls. Trusted signature mode requires PyNaCl to be included in the offline dependency bundle. Full air-gap packaging is not formally tested. |

---

## What this means for a pilot specifically

A **scoped, single-workflow partner sandbox** (per `PILOT-SCOPE.md`) is
supportable: the authorization findings from the 19 October 2026 external
review are fixed (authority freshness, ADR 0024; capability-to-operation
binding, ADR 0025; server-derived permit evidence, ADR 0026). Run it with
the secure profile and a reviewed operations file, and see
`docs/ROADMAP.md` for the deployment findings still open.

A **multi-host, monitored, horizontally-scaled production deployment with
formal certification** is not supportable today. Multiple instances are
correct on one PostgreSQL; their performance across hosts and at a large
ledger is unmeasured, and this document exists so that gap is stated
plainly rather than discovered during a bank's infrastructure review.

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
