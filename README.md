# PrivateVault Agent DNA

Decision security runtime for autonomous AI agents. Sits between an
agent and its executors, evaluates every action against a fixed
precedence of deterministic rules before it runs, and writes a
hash-chained record of what was decided and why. The audit trail has an independent chain verifier that uses only the
Python standard library. Trusted origin verification additionally consumes
detached envelopes and auditor-supplied Ed25519 public keys.

The learned component (behavioral drift scoring) is advisory. It can
escalate an action for review. It cannot approve one. Enforcement is
deterministic, replayable, and fail-closed: an internal fault in the
decision path produces a BLOCK, not an exception and not a pass.

```
agent ──► POST /v1/decide ──► precedence engine ──► 200 / 202 / 403
                                    │
                                    ▼
                          hash-chained records ──► verify_records.py
```

## Quick start

```bash
pip install -e ".[dev]"
python -m pytest -q                    # 986+ tests
```

Three properties worth checking before reading further:

```bash
# fail-closed enforcement, end to end, with a log-tamper demo
python examples/composed_line_demo.py

# 11 adversarial scenarios against the precedence ladder
python tools/run_adversarial.py

# chain verification: standard library only
python tools/verify_records.py <audit export .jsonl>

# trusted signature verification: requires PyNaCl
python tools/verify_records.py <audit export .jsonl> \
  --envelopes <envelope export .jsonl> \
  --trusted-key <trusted public key>

# deterministic cross-agent security loop discovery
pv loop discover --input examples/loop_discovery/clean.jsonl \
  --json /tmp/loop-report.json

# offline policy discovery: mine, replay, evaluate, propose (never apply)
pv discover run --history-db decisions.db \
  --replay-db decisions.db.replay.db --replay-fields amount \
  --adversarial-fixture examples/discovery_loop/adversarial.jsonl \
  --json /tmp/discovery-report.json --out-dir /tmp/discovery-proposals
python tools/verify_discovery.py /tmp/discovery-report.json
```

As a service (dev, auth off):

```bash
PV_ALLOW_NO_AUTH=1 docker compose up --wait  # local development only
curl -i -X POST localhost:8000/v1/decide \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"a1","capability":"crm.read_contact","timestamp":0}'
```

Self-hosted platform profile (auth on, console, Prometheus):

```bash
uv run python tools/init_platform_keys.py
export PV_API_KEYS_FILE=$PWD/deploy/platform/keys.json
docker compose -f docker-compose.platform.yml up --build --wait
# console http://localhost:8080  ·  metrics http://localhost:9090  ·  API :8000
uv run python tools/platform_demo.py   # in-process proof without Docker
```

The HTTP status code is the verdict: `200` allow, `202`
require_approval, `403` block.

Production startup is fail-closed: configure `PV_API_KEYS_FILE`, or the service
refuses to start. `PV_ALLOW_NO_AUTH=1` is an explicit local-development escape
hatch and must never be used on a networked deployment.

## PrivateVault Discovery Loop

`agent_dna.discovery` closes a low-compute, offline experimental cycle over
sealed decision evidence: mine candidate controls, run additive shadow replay
against history and a committed adversarial corpus, evaluate deterministic
gates and structural probes, then emit ranked, evidence-linked PR proposals.
Nothing is applied automatically. The report has a strict wire contract and an
independent standard-library verifier. Learned validation remains advisory and
the online L0-L7 path is unchanged. See `docs/DISCOVERY-LOOP.md` and
`spec/discovery-loop-v1/`.

## Multi-agent enforcement (live path)

Cross-agent behavioral invariants (CABI) attach by default in production
composition. On `POST /v1/decide` and the connector, a declared
`execution_id` (or MCP `_pv_execution_id`) opens a correlation window.
Definitional dual-control blocks the same agent initiating and approving
in that window; structural approval cycles are hard blocks. Verdicts only
escalate — never relax. Disable with `PV_CROSS_AGENT=0`.

## Agent security loop detector

`agent_dna.security.loop_discovery` performs bounded, deterministic graph
analysis before consequential multi-agent dispatch. On
`POST /v1/authorize`, supply `security_events` to refuse `BLOCK`/`REVIEW`
before a single-use permit is minted. It distinguishes circular
authority from ordinary request/response traffic:

| Evidence | Outcome |
|---|---|
| Delegation or approval cycle | `BLOCK` |
| Reused single-use authorization | `BLOCK` |
| Causal parent cycle, cross-trace parent, or excess depth | `BLOCK` |
| Second identical action in one lineage | `REVIEW` |
| Third identical action in one lineage | `BLOCK` |
| Bidirectional invocation without stronger evidence | `REVIEW` |

The analyzer uses strict schemas, rejects unknown fields, emits stable witness
paths and report digests, and makes no model or network calls. A digest is an
integrity identifier, not proof of dispatch; production adapters must retain the
input events and report beside signed authorization, witness, and closure
evidence. See `docs/LOOP-DISCOVERY.md` and `spec/loop-discovery-v1/`.

## Decision model

Every action descends a strict precedence order. First firing level
wins. The order is committed as a hash-pinned contract
(`spec/contracts/precedence-order.json`) and CI fails the build if
the code drifts from it (`tests/test_precedence_contract.py`).

| Level | Layer                 | Nature                          | On trigger              |
|-------|-----------------------|---------------------------------|-------------------------|
| L0    | Enterprise constraints| deterministic, evidence-checked | BLOCK                   |
| L1    | Behavioral invariants | deterministic contract          | BLOCK                   |
| L2    | Customer policy       | deterministic, data-driven      | BLOCK / REQUIRE_APPROVAL|
| L3    | Multi-agent consensus | evidence-gated, signed votes    | REQUIRE_APPROVAL        |
| L4    | Capability grants     | deterministic authz             | REQUIRE_APPROVAL        |
| L5    | Economics             | deterministic cost/ROI check    | REQUIRE_APPROVAL        |
| L6    | Learned drift         | probabilistic, advisory only    | REQUIRE_APPROVAL        |
| L7    | Baseline              |                                 | ALLOW                   |

Properties that hold across the engine, each backed by named tests:

- A deterministic DENY is final. No signal below it, learned or
  otherwise, converts it to an allow.
- Missing evidence causes a check to SKIP, visibly, in the record.
  It is never treated as a pass (`test_fail_closed.py`).
- Any exception inside the decision path becomes `engine_fault` and a
  BLOCK (`test_api_fail_closed.py`, `test_nonfinite_guard.py`).
- Denied actions never advance the behavioral baseline
  (`test_runtime_enforcement.py`).
- The store survives restarts with chain state intact
  (`test_restart_survival.py`) and concurrent writers
  (`test_multi_writer_safety.py`).

## Audit trail

Each decision is a sealed record: SHA-256 over canonical content,
chained per agent, optionally signed with Ed25519. Execution outcomes
are anchored back to the decision that authorized them.

| Tampering attempt                       | Detected by            |
|-----------------------------------------|------------------------|
| Edit any field of any record            | record_hash mismatch   |
| Delete or reorder records               | per-agent chain break  |
| Forge an execution result               | anchor mismatch        |
| BLOCK recorded, action ran anyway       | enforcement divergence |

`tools/verify_records.py` re-derives chain integrity from the record export.
With detached envelopes and independently supplied keys, it also verifies
trusted signing origin. Wire format, JSON Schemas, and canonical vectors are
published
separately as the DRP specification
([github.com/LOLA0786/drp-spec](https://github.com/LOLA0786/drp-spec),
Apache-2.0 / CC-BY-4.0), so verification does not depend on trusting
this repository.

## HTTP API

`POST /v1/decide` is the enforcement surface. Companion endpoints:
`/v1/outcome` (executor feedback), `/v1/envelope/{hash}` (signature
retrieval), `/v1/blocked`, `/v1/divergent`, `/v1/lineage/{id}`
(queries), `/v1/verify` and `/v1/audit/export` (verifier-ready
JSONL), `/metrics` (Prometheus). API keys are SHA-256-hashed at rest
and scoped; an audit-scoped key cannot call `/v1/decide`
(`test_api_audit_scope.py`).

## MCP

Two integration layers:

1. Advisory tools over the composed decision line
   (`agent_dna/mcp_server.py`): `pv_decide`, `pv_report_outcome`,
   `pv_verify`, `pv_lineage`, `pv_blocked`, `pv_divergent`. Run with
   `python -m agent_dna.mcp_server`.
2. Transport-level enforcement: the connector wraps any FastMCP
   server so every `tools/call` passes through the precedence line
   before the tool executes, with per-session agent identity and
   signed refusals in-band (`tests/connector/`).

## Model validation

The drift scorer is evaluated with a sealed report format,
`pv-validation/1`: per-segment reliability (agent, capability,
agent×capability) with Wilson intervals, an exact decomposition of
global AUC into within-segment and between-segment contributions,
and calibration metrics (Brier, log loss, ECE) computed only for
scores declared as probabilities. Requesting calibration numbers for
a ranking score raises, and the independent verifier
(`tools/verify_validation.py`, stdlib only) rejects such a report
even if correctly resealed.

A validation report can tighten the drift threshold at runtime
(`ValidationGuard`, env `PV_VALIDATION_REPORT`). It cannot loosen
it, and it cannot reach L0 through L4. Formulas and limitations:
`docs/VALIDATION-MATH.md`.

## Architecture

```
execution traces
      │
CapabilityManifold      capability vocabulary, argument distributions
BehaviorDynamics        Markov transition model over capability order
      │
DriftScorer ──► AdvisorySignal (score, severity, reasons)
      │
DecisionEngine          L0..L7 precedence, fail-closed
RuntimeMonitor          enforcing streaming path
DecisionRecorder        sealed, hash-chained records
DecisionStore           append-only (JSONL or SQLite/WAL)
ReceiptSigner           optional Ed25519 over record_hash
ExecutionEvents         executor feedback, anchored per decision
DecisionGraph           lineage, blocked, divergence queries
      │
tools/verify_records.py independent chain and signature verifier
```

## Layout

| Path | Contents |
|---|---|
| `agent_dna/trace.py` | Data contract: `AgentAction`, `ExecutionTrace` |
| `agent_dna/manifold.py`, `dynamics.py` | Learned profile |
| `agent_dna/scorer.py`, `advisory.py` | Drift score with per-factor reasons |
| `agent_dna/decision.py` | Precedence engine. The enforcement boundary |
| `agent_dna/uaal_layer.py` | L0 enterprise constraints |
| `agent_dna/policy/` | L2 customer policy: YAML/JSON rules, first match wins |
| `agent_dna/consensus/` | L3 signed multi-agent voting, evidence-gated |
| `agent_dna/grants.py` | L4 capability grants: expiry, revocation, budgets |
| `agent_dna/economics/` | L5 cost-ratio anomaly and ROI floor |
| `agent_dna/validation/` | pv-validation/1 metrics, reports, runtime guard |
| `agent_dna/circuit_breaker.py` | Spending and frequency breakers, group suspension |
| `agent_dna/multi_agent/` | Cross-agent topology, temporal, authority, trust, and consensus invariants |
| `agent_dna/security/loop_discovery.py` | Deterministic authority/replay/causal-loop analyzer |
| `agent_dna/discovery.py` | Offline mine/replay/evaluate/rank policy discovery runner |
| `agent_dna/decision_record.py`, `decision_recorder.py`, `decision_graph.py` | Sealed records, chaining, lineage |
| `agent_dna/decision_store.py`, `sqlite_store.py` | Append-only persistence |
| `agent_dna/signer.py`, `apikeys.py` | Ed25519 receipts, hashed API keys |
| `api/server.py` | FastAPI decision service |
| `agent_dna/mcp_server.py`, `connector/` | MCP tools and transport enforcement |
| `spec/` | Wire format: schemas, canonical vectors, precedence contract |
| `tools/` | Independent verifiers, benchmarks, and adversarial runners |
| `experimental/` | Unwired sketches. Nothing here carries claims |

## Verify without trusting our later handling of evidence

Procurement / third-party risk one-pager:
[`docs/VERIFY-WITHOUT-TRUSTING-US.md`](docs/VERIFY-WITHOUT-TRUSTING-US.md)
(stdlib verifier, proof-of-run, refuse codes, `pvscan`). Cite git commit +
`report_hash` together.

## Limitations

Read `docs/WHAT-WE-DO-NOT-CLAIM.md` before depending on this in
production. The short version:

- Behavioral profiles ship calibrated on labelled synthetic traces.
  Accuracy figures are synthetic until profiled on real execution
  traces; the API's root endpoint states this in its `calibration`
  field.
- No SOC 2 or ISO 27001 certification, and none in progress.
- Determinism means replayability under a pinned policy version, not
  formal verification.
- MCP transport enforcement has not been load-tested under high
  concurrent client counts.
- Cross-agent invariants are wired only when a connector supplies a declared
  execution correlation window. The runtime does not infer missing correlation.
- Loop discovery is a deterministic analyzer and CLI; each production adapter
  remains responsible for invoking it at the authority boundary and retaining
  its report with dispatch evidence.
- The offline Discovery Loop proposes policy changes but cannot approve, merge,
  or deploy them. Corpus Wilson intervals are not production accuracy claims.

## Security

Threat model, trust assumptions, and residual risks:
`docs/SECURITY.md`. Vulnerability reports:  chandan.galani@privatevault.ai.
Signing keys are environment or file based and never committed;
found-and-fixed issues (a timing side-channel in HMAC comparison, a
scope-enforcement regression) are documented there with their
regression tests.

## License

Apache-2.0. See `LICENSE`. The DRP wire specification is published
under Apache-2.0 / CC-BY-4.0 in its own repository.
OWNER- PENTAPRIME SOLUTIONS , INC 
