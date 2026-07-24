# PrivateVault — HTTP API Surface

Version 0.2.1. This document describes the enforcement and audit
endpoints an external client consumes. It is the contract an operator
console, an SDK, or an integration builds against.

Companion documents:

- **Wire format** — `github.com/LOLA0786/drp-spec` (Apache-2.0 /
  CC-BY-4.0). Record schemas, canonical test vectors, and a
  standard-library verifier.
- **Threat model** — `docs/SECURITY.md`
- **Stated limitations** — `docs/WHAT-WE-DO-NOT-CLAIM.md`

---

## Authentication

All endpoints require an API key in the `X-API-Key` header.

Two scopes:

| Scope | Grants |
|---|---|
| `full` | Every endpoint, including enforcement |
| `audit` | Read-only audit endpoints only (`/v1/verify`, `/v1/audit/export`) |

An `audit` key is explicitly rejected on enforcement endpoints. Full
scope satisfies audit requirements; the reverse does not.

**Identity binding.** The authenticated credential is the
authoritative agent identity. A key issued for agent A cannot submit
actions as agent B, and cannot read agent B's records — the
`agent_id` in a request body is checked against the credential, not
trusted from it.

**Startup behavior.** The service refuses to start when no keys are
configured, unless `PV_ALLOW_NO_AUTH=1` is set explicitly. Missing
configuration is a refused startup, never an open endpoint.

---

## Enforcement

### `POST /v1/decide`

Submit a proposed action for a decision. This is the enforcement
surface; the HTTP status code carries the verdict.

**Request**

```json
{
  "agent_id": "treasury-agent-07",
  "capability": "payments.transfer",
  "timestamp": 1753000000.0,
  "arguments": {"amount": 4200000, "counterparty": "acme-logistics"},
  "context": {},
  "evidence": {
    "user_request": {"canonical_target": "INV-88412"},
    "planner": {"canonical_target": "INV-88412"},
    "approvals": {"required": false}
  },
  "request_id": "req-9a8b-7c"
}
```

| Field | Type | Notes |
|---|---|---|
| `agent_id` | string | Must match the authenticated credential |
| `capability` | string | Fully-qualified action name |
| `timestamp` | float | Unix seconds |
| `arguments` | object | Action parameters. Digested, never stored raw |
| `context` | object | Optional runtime context |
| `evidence` | object | Declared intent, planner target, approvals |
| `request_id` | string \| null | Correlation id; carried into the sealed record |

**Response status is the verdict**

| Status | Verdict |
|---|---|
| `200` | allow |
| `202` | require_approval |
| `403` | block |

**Response body** (same shape for all three)

```json
{
  "decision": "block",
  "triggered_by": "policy",
  "reason": "transfers above the autonomous ceiling require dual control",
  "record": { "...": "the sealed DecisionRecord, see drp-spec" }
}
```

`triggered_by` names the precedence level that fired — this is what a
console should display as the cause. It is a rule name, not a score.

**Notes for client authors.** A non-200 is a verdict, not an error.
Do not retry a 403. Any internal fault in the decision path returns a
deterministic block rather than a 500 — a client that treats 5xx as
transient will never see a fail-open.

---

### `POST /v1/outcome`

Report what actually happened after a decision. This is what makes
enforcement divergence detectable.

```json
{
  "decision_id": "d-4f13d3c0",
  "status": "ok",
  "detail": ""
}
```

`status` is one of `ok`, `error`, `refused`. The resulting execution
event is hash-anchored to the decision it references.

If a decision was `block` and its outcome reports `ok`, verification
fails with ENFORCEMENT DIVERGENCE. Clients should report outcomes
honestly; the point of the field is to make dishonesty visible, not to
be a formality.

---

## Query surface

These are the endpoints a console renders. All are scoped to the
authenticated agent unless the credential is an operator key.

### `GET /v1/records/{agent_id}`

Full decision history for one agent, in chain order.

```json
{
  "agent_id": "treasury-agent-07",
  "records": [ {"...": "DecisionRecord"}, "..." ]
}
```

### `GET /v1/blocked`

Every blocked decision.

```json
{"blocked": [ {"...": "DecisionRecord"}, "..." ]}
```

### `GET /v1/divergent`

Decisions where the recorded verdict and the reported outcome
disagree. For an operator console this is the highest-priority view.

```json
{"divergent": [ {"...": "DecisionRecord"}, "..." ]}
```

### `GET /v1/lineage/{decision_id}`

The chain of decisions leading to and from one decision.

```json
{"lineage": [ {"...": "DecisionRecord"}, "..." ]}
```

### `GET /v1/runtime`

Composition manifest: which enforcement levels are attached and why
the rest are not. An honesty surface, so an operator can see what a
deployment actually enforces rather than what it advertises.

```json
{"composition": {"...": "per-level status and detail"}}
```

---

## Audit surface

`GET /v1/verify` runs chain verification across all agents.
`GET /v1/audit/export` streams the full record set as JSONL in the DRP
wire format. `GET /v1/envelope/{record_hash}` returns the Ed25519
signature envelope for a sealed record. Export and verify require
`audit` or `full` scope.

Signatures are over the `record_hash`, never over a re-serialized
body. Rationale in `drp-spec/docs/SIGNING.md`.

## Operational

`GET /` returns service metadata including a `calibration` field.
`GET /health` is liveness. `GET /metrics` is Prometheus exposition and
requires `audit` or `full` scope.

## Verification is independent by design

A record's validity must never depend on the code that displays it.

`drp-spec` ships `verify_records.py`, standard library only, importing
nothing from this runtime. Any consumer can check an export
themselves. It verifies record hashes, per-agent chain continuity,
execution anchor binding, field-set conformance, ID uniqueness,
lineage binding, and enforcement divergence.

For a console this is a hard constraint: it renders evidence and must
not become a component an auditor has to trust. It should never be the
only path to verification, never re-serialize records before hashing,
and never present a derived view that could be mistaken for the record
itself.

## What this API does not do

- It does not mediate actions that never pass through it. Complete
  mediation requires infrastructure containment on the customer side.
- Single-instance. No multi-node coordination.
- Not load-tested at high concurrency; no latency or throughput
  figures are published.
- Behavioral profiles are calibrated on synthetic traces until a pilot
  supplies independently labelled real outcomes.
