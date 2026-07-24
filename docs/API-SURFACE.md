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
