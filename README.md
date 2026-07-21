# PrivateVault Agent DNA™ — Behavioral Identity & Decision Security Runtime

Identity tells you who an agent is. Agent DNA tells you whether the
agent is still behaving like itself — and refuses, records, and
proves it when it isn't.

A Python runtime that (1) learns an autonomous agent's trusted
operational profile from execution traces, (2) enforces decisions
pre-execution through a deterministic precedence model, and (3) emits
a tamper-evident, independently verifiable decision audit trail.

## Status & 5-minute demo

**Maturity:** pilot-ready runtime, pre-certification. Enforced today:
the full 8-level deterministic precedence line (L0-L7), fail-closed
faults, hash-chained + optionally Ed25519-signed records, scoped API
keys, MCP transport enforcement, circuit breakers, multi-agent
invariants/consensus, and a sealed validation format (pv-validation/1)
for the advisory drift layer. Not claimed: SOC 2/ISO, formal proofs,
real-trace-calibrated baselines, MCP high-concurrency load — the full
honest list is in [`docs/WHAT-WE-DO-NOT-CLAIM.md`](docs/WHAT-WE-DO-NOT-CLAIM.md).

Five minutes, three properties, reproducible:

    pip install -e ".[dev]"
    python -m pytest -q                       # full suite, must be green

    # 1. fail-closed + precedence, end to end with a tamper demo
    python examples/composed_line_demo.py

    # 2. adversarial corpus: 11 attack scenarios against the ladder
    python tools/run_adversarial.py

    # 3. independent verification — deliberately NOT our code path:
    #    verify the audit export with one stdlib-only file
    python tools/verify_records.py <exported .jsonl from step 1 output dir>

Or as a service:

    docker compose up --wait
    curl -i -X POST localhost:8000/v1/decide \
      -H 'Content-Type: application/json' \
      -d '{"agent_id":"a1","capability":"crm.read_contact","timestamp":0}'
    # HTTP status IS the verdict: 200 allow / 202 require_approval / 403 block

## The non-negotiable property

The learned model is advisory. The deterministic layers decide.
`decision.py` encodes this as a strict precedence order — observable
in every record's `triggered_by` field:

    L0. enterprise constraints  (deterministic, evidence-checked)   -> BLOCK
    L1. behavioral invariants   (deterministic contract)            -> BLOCK
    L2. customer policy         (deterministic, data-driven rules)  -> BLOCK / REQUIRE_APPROVAL
    L3. multi-agent consensus   (evidence-gated, signed voting)     -> REQUIRE_APPROVAL
    L4. capability grants       (deterministic authz)               -> REQUIRE_APPROVAL
    L5. economics               (deterministic cost/ROI check)      -> REQUIRE_APPROVAL
    L6. learned drift           (probabilistic advisory)            -> REQUIRE_APPROVAL
    L7. baseline                                                    -> ALLOW

A deterministic DENY is final: nothing below it — including drift or
cost signals — can ever turn it into an ALLOW. Learned signals can
only raise scrutiny, never lower it. The ML adds earlier warning, not
a new bypass. In BFSI/healthcare terms: the security boundary is
deterministic and auditable; the model explains, the rules decide.

The exact order above is not just documented — it's a committed,
hash-pinned contract (`spec/contracts/precedence-order.json`) that CI
verifies against the actual code on every push. If the order ever
drifts from the contract without a deliberate, reviewed update, the
build fails.

## Architecture

    execution traces
          |
    CapabilityManifold (what's normal: vocab + arg distributions)
    BehaviorDynamics   (normal ordering: Markov transition model)
          |
    DriftScorer -> AdvisorySignal (score + severity + reasons)
          |
    DecisionEngine     precedence: eight contract levels (L0-L7) above; fail-closed on any
          |            internal fault (engine_fault -> BLOCK, never
          |            a silent pass or unhandled crash)
    RuntimeMonitor     enforcing streaming path; denied actions
          |            never advance the behavioral baseline
    DecisionRecorder -> sealed, hash-chained DecisionRecords
          |            (chain state restored from store on restart)
    DecisionStore      append-only (JSONL or SQLite/WAL)
          |
    ReceiptSigner      optional Ed25519 signing over record_hash
          |
    ExecutionEvents    executor feedback, hash-anchored per decision
          |
    DecisionGraph      queryable lineage / blocked / divergence
          |
    tools/verify_records.py   stdlib-only independent auditor

## What the audit layer proves

| Attack on the log                       | Caught by               |
|------------------------------------------|--------------------------|
| Edit any field of any record              | record_hash mismatch     |
| Delete or reorder records                 | per-agent chain break    |
| Forge an execution result                 | anchor mismatch          |
| Runtime says BLOCK, action ran anyway     | ENFORCEMENT DIVERGENCE   |

Verification requires nothing but Python 3 and one file — no
dependency on this codebase. Canonical test vectors and JSON Schemas
live in `spec/`, published separately as the open DRP specification:
github.com/LOLA0786/drp-spec (Apache-2.0 / CC-BY-4.0).

## HTTP API

The enforcement surface is `POST /v1/decide`; the HTTP status code IS
the signal:

    200  allow
    202  require_approval
    403  block

API-key authenticated (SHA-256 hashed at rest); companion endpoints
for outcome reporting (`/v1/outcome`), signature retrieval
(`/v1/envelope/{hash}`), queries (`/v1/blocked`, `/v1/divergent`,
`/v1/lineage/{id}`), and audit (`/v1/verify`,
`/v1/audit/export` — verifier-ready JSONL).

## MCP

The composed decision line is also exposed as MCP tools
(`agent_dna/mcp_server.py`): `pv_decide`, `pv_report_outcome`,
`pv_verify`, `pv_lineage`, `pv_blocked`, `pv_divergent`. Run
standalone: `python -m agent_dna.mcp_server`.

## Run it

    # dev
    pip install -e ".[dev]" --break-system-packages
    python -m pytest -q                            # 452 tests
    python examples/composed_line_demo.py           # full 6-level pipeline + tamper demo
    python tools/run_adversarial.py                 # 11-scenario adversarial corpus
    python tools/benchmark.py 5000                  # reproducible throughput benchmark

    # service
    docker compose up
    curl -i -X POST localhost:8000/v1/decide \
      -H 'Content-Type: application/json' \
      -d '{"agent_id":"a1","capability":"crm.read_contact","timestamp":0}'

## Modules

| Module | Role |
|---|---|
| `trace.py` | Data contract: `AgentAction`, `ExecutionTrace` |
| `manifold.py` / `dynamics.py` | Learned profile: capability vocabulary, argument distributions, Markov ordering |
| `scorer.py` / `advisory.py` | Decomposed drift score with one-sentence reasons |
| `decision.py` | Precedence engine — the enforcement boundary, fail-closed |
| `uaal_layer.py` | L0 enterprise constraints (vendored + tested from UAAL's EAV engine) |
| `grants.py` | Capability grants — expiry, revocation, budget, named-reason denials |
| `economics/` | L3 pre-execution cost-ratio anomaly + ROI floor check |
| `consensus/` | Weighted and signed (HMAC) multi-agent voting — L3 in the precedence order (v4.0: policy is L2), evidence-gated (absent evidence skips) |
| `runtime.py` | Enforcing streaming monitor |
| `decision_record.py` / `execution_record.py` | Sealed, hash-chained record kinds (drp/0.1) |
| `decision_graph.py` / `decision_recorder.py` | Queryable lineage, chain verification, restores from store on startup |
| `decision_store.py` / `sqlite_store.py` | Append-only persistence (JSONL / SQLite WAL) |
| `signer.py` | Ed25519 signing over record_hash per drp-spec SIGNING.md |
| `apikeys.py` | Hashed API-key authentication |
| `multi_agent/` | Cross-agent behavioral invariants (topology, temporal, authority, consensus) — tested library, not yet wired into the serving path |
| `api/server.py` | FastAPI decision service |
| `mcp_server.py` / `mcp_gateway.py` | MCP tool exposure of the composed decision line |
| `spec/` | Open wire format: JSON Schemas, canonical test vectors, adversarial corpus, precedence-order contract |
| `tools/verify_records.py` | Independent, stdlib-only audit verifier |
| `tools/benchmark.py` | Reproducible throughput benchmark with stated methodology |
| `tools/run_adversarial.py` | 11-scenario adversarial corpus runner, built for external review |

## Calibration honesty

Behavioral profiles in the demos and the default API are trained on
clearly-labelled synthetic traces (`adapters.py`). Thresholds and
accuracy figures are synthetic-calibrated; production deployment
requires profiling on real execution traces. This is stated in the
API's root endpoint (`calibration` field) deliberately.

See `docs/WHAT-WE-DO-NOT-CLAIM.md` for the full, explicit list of
what is not yet shipped, including certification status, deployment
maturity, and multi-agent enforcement.

## Relationship to PrivateVault.ai

This is the canonical, tested runtime. Several components here were
vendored from the PrivateVault.ai repository's less mature modules
after those modules were found to have zero test coverage on
inspection — `uaal_layer.py` (from UAAL's EAV engine), `consensus/`
(from `pv_runtime_v2` and `coordination/mesh`), and `economics/`
(from `pv_economics`) were each re-verified with tests written fresh
against the vendored logic before being trusted here. One real
security bug (a timing side-channel in HMAC signature comparison) was
found and fixed during that process.

## Build Status (v0.2.0 industrial update)

- Packaging: `pyproject.toml` strict (`ruff`, `mypy`, `pydantic`, `cryptography`)
- Consensus: `AgentAction` native `evidence` + `DecisionEngine` auto-merge
- Observability: `agent_dna/observability/` (JSON logger, metrics exporter)
- Security: `docs/SECURITY.md`, Ed25519 rotation stub (`signer.py`)
- Fail-closed: any exception in decision path -> BLOCK
