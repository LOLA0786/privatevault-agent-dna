# PrivateVault Agent DNA™ — Behavioral Identity & Decision Security Runtime

Identity tells you who an agent is. Agent DNA tells you whether the
agent is still behaving like itself — and refuses, records, and proves
it when it isn't.

A Python runtime that (1) learns an autonomous agent's trusted
operational profile from execution traces, (2) enforces decisions
pre-execution through a deterministic precedence model, and (3) emits
a tamper-evident, independently verifiable decision audit trail.

## The non-negotiable property

The learned model is advisory. The deterministic layers decide.
`decision.py` encodes this as a strict precedence order — observable
in every record's `triggered_by` field:

    1. behavioral invariants   (deterministic contract)  -> BLOCK
    2. capability grants       (deterministic authz)     -> REQUIRE_APPROVAL
    3. learned drift           (probabilistic advisory)  -> REQUIRE_APPROVAL
    4. baseline                                          -> ALLOW

A deterministic DENY is final: drift scores can never turn it into an
ALLOW. Learned signals can only raise scrutiny, never lower it. The ML
adds earlier warning, not a new bypass. In BFSI/healthcare terms:
the security boundary is deterministic and auditable; the model
explains, the rules decide.

## Architecture

    execution traces
          |
    CapabilityManifold (what's normal: vocab + arg distributions)
    BehaviorDynamics   (normal ordering: Markov transition model)
          |
    DriftScorer -> AdvisorySignal (score + severity + reasons)
          |
    DecisionEngine     precedence: invariant > authz > drift > allow
          |
    RuntimeMonitor     enforcing streaming path; denied actions
          |            never advance the behavioral baseline
    DecisionRecorder -> sealed, hash-chained DecisionRecords
          |
    DecisionStore      append-only (JSONL or SQLite/WAL)
          |
    ExecutionEvents    executor feedback, hash-anchored per decision
          |
    DecisionGraph      queryable lineage / blocked / divergence
          |
    tools/verify_records.py   stdlib-only independent auditor

## What the audit layer proves

| Attack on the log                     | Caught by              |
|---------------------------------------|------------------------|
| Edit any field of any record          | record_hash mismatch   |
| Delete or reorder records             | per-agent chain break  |
| Forge an execution result             | anchor mismatch        |
| Runtime says BLOCK, action ran anyway | ENFORCEMENT DIVERGENCE |

Verification requires nothing but Python 3 and one file — no
dependency on this codebase. Canonical test vectors and JSON Schemas
live in `spec/`.

## HTTP API

The enforcement surface is `POST /v1/decide`; the HTTP status code IS
the signal:

    200  allow
    202  require_approval
    403  block

Plus `/v1/outcome` (anchored executor feedback), query endpoints
(`/v1/blocked`, `/v1/divergent`, `/v1/lineage/{id}`), and an audit
surface (`/v1/verify`, `/v1/audit/export` — verifier-ready JSONL).

## Run it

    # dev
    pip install -e ".[dev]" --break-system-packages
    python -m pytest -q                      # 100 tests
    python examples/end_to_end_demo.py       # full pipeline + tamper demo

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
| `decision.py` | Precedence engine — the enforcement boundary |
| `runtime.py` | Enforcing streaming monitor |
| `decision_record.py` / `execution_record.py` | Sealed, hash-chained record kinds |
| `decision_graph.py` / `decision_recorder.py` | Queryable lineage, chain verification |
| `decision_store.py` / `sqlite_store.py` | Append-only persistence (JSONL / SQLite WAL) |
| `multi_agent/` | Cross-agent behavioral invariants (topology, temporal, authority, consensus) |
| `api/server.py` | FastAPI decision service |
| `spec/` | Open wire format: JSON Schemas + canonical test vectors |
| `tools/verify_records.py` | Independent, stdlib-only audit verifier |

## Calibration honesty

Behavioral profiles in the demos and the default API are trained on
clearly-labelled synthetic traces (`adapters.py`). Thresholds and
accuracy figures are synthetic-calibrated; production deployment
requires profiling on real execution traces. This is stated in the
API's root endpoint (`calibration` field) deliberately.

## Relationship to the PrivateVault runtime

This repo is the behavioral identity and decision-graph layer. The
PrivateVault enforcement runtime adds Ed25519 receipt signing,
approval binding, and replay on top of the same record format. The
wire format itself is being extracted to a standalone open
specification (`spec/` is its staging ground). `receipt_ref` on
DecisionRecords is the signing seam — schema-reserved until the
binding lands.
