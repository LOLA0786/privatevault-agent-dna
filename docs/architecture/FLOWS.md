# Flows

What happens, in order, for each thing PrivateVault does. Every step names
the function that does it; `tests/test_architecture_doc.py` fails if any of
those names stops existing. For one `/v1/decide` call in full detail (monitor,
breaker, ladder) see [../../ARCHITECTURE.md](../../ARCHITECTURE.md).

Separation holds only for covered flows where enforcement is enabled and
verified.

## The whole path of a state-changing action

```mermaid
sequenceDiagram
    autonumber
    participant Ag as Agent
    participant API as Decision API
    participant Hu as Approver
    participant SC as Exact-byte sidecar
    participant RG as Receiver gate
    participant Up as System of record
    Ag->>API: POST /v1/decide (action, sealed dispatch values)
    API-->>Ag: 200 allow / 202 approval / 403 block + signed record
    opt 202 approval
        Hu-->>Ag: signed approval artifact (approval_v01)
        Ag->>API: POST /v1/decide again, with the approval
        API-->>Ag: 200 allow (approval consumed once)
    end
    Ag->>API: POST /v1/authorize (record hash, exact bytes)
    API-->>Ag: single-use permit, signed, bound to the bytes
    Ag->>SC: send these bytes with this permit
    SC->>SC: verify permit offline, consume it, freeze bytes
    SC->>RG: same bytes + permit header, over mTLS
    RG->>RG: verify permit, presenter, bytes, revocation, claim once
    RG->>Up: forward
    Up-->>RG: response
    RG-->>SC: response + signed receiver receipt
    SC->>SC: sign dispatch witness and closure
    Ag->>API: POST /v1/outcome (status, response digest)
```

Each box can run without the next one: a deployment can decide without
minting, mint without a receiver gate, and so on. What is enforced is what is
attached; `GET /v1/runtime` reports it.

## HTTP routes

Every route `api/server.py` serves. `test_every_route_is_documented` fails if
a route is added without a row here.

| Method and path | Handler | Key | What it does |
|---|---|---|---|
| `POST /v1/decide` | `api/server.py::decide` | full | Decide one action, seal and sign the record |
| `POST /v1/outcome` | `api/server.py::outcome` | full | Append what happened after an ALLOW |
| `POST /v1/authorize` | `api/server.py::authorize` | full | Mint a single-use permit for a sealed, bound ALLOW |
| `GET /v1/runtime` | `api/server.py::runtime_composition` | full | Which enforcement levels are attached, and why the rest are not |
| `GET /v1/records/{agent_id}` | `api/server.py::records` | full (own agent) | That agent's records |
| `GET /v1/blocked` | `api/server.py::blocked` | full (own agent) | Blocked records |
| `GET /v1/divergent` | `api/server.py::divergent` | full (own agent) | BLOCKed records the executor reported as executed anyway |
| `GET /v1/lineage/{decision_id}` | `api/server.py::lineage` | full (own agent) | Server-derived lineage of a decision (ADR 0021) |
| `GET /v1/revocations` | `api/server.py::revocations` | audit or full | Signed revocation list for receivers |
| `GET /v1/flows/{flow_id}` | `api/server.py::flow_export` | audit or full | Every record in one multi-agent flow |
| `GET /v1/envelope/{record_hash}` | `api/server.py::envelope` | full | Signed envelope of one record |
| `GET /v1/verify` | `api/server.py::verify` | audit or full | Re-verify every chain in the store |
| `GET /v1/audit/export` | `api/server.py::audit_export` | audit or full | All records as JSONL |
| `GET /v1/audit/envelopes` | `api/server.py::audit_envelope_export` | audit or full | All envelopes as JSONL |
| `GET /v1/ops/summary` | `api/server.py::ops_summary` | audit or full | Counts for the operator console |
| `GET /` | `api/server.py::root` | none | Service description |
| `GET /health` | `api/server.py::health` | none | Process is up |
| `GET /ready` | `api/server.py::ready` | none | Store answers a ping; reports auth and signing posture |
| `GET /metrics` | `api/server.py::prometheus_metrics` | none | Prometheus metrics |

"full" is an operator or agent key; "own" means the key must own the
agent. An audit-scoped key reads only the audit routes; it cannot decide,
mint or report outcomes (`api/server.py::require_api_key`).

## Decide

Covered in full in [../../ARCHITECTURE.md](../../ARCHITECTURE.md). The order
inside `api/server.py::decide`:

1. Key to principal, and the key must own `agent_id`
   (`api/server.py::_enforce_identity`); DRP 0.2 binding checks
   (`api/server.py::_validate_decide_binding`).
2. An approval, if one is attached, is checked for whether it can be judged
   at all (`api/server.py::_approval_context_for`).
3. The sealed destination and operation are exposed to policy as
   `evidence.bound`; callers cannot set it themselves.
4. Monitor, breaker, engine and precedence ladder
   (`agent_dna/runtime.py::RuntimeMonitor.process`).
5. Cross-agent escalation (`agent_dna/connector/cross_agent.py::escalate_with_cross_agent`)
   and lineage escalation (`agent_dna/lineage.py::escalate_with_lineage`).
   Both can only tighten.
6. Seal, sign and store record and envelope together
   (`agent_dna/decision_recorder.py::DecisionRecorder.record`), then record
   the lineage event (`agent_dna/lineage.py::LineageLedger.record`).
7. HTTP status from the verdict: 200 allow, 202 approval, 403 block.

## Approval (ADR 0020)

```mermaid
sequenceDiagram
    autonumber
    participant Ag as Agent
    participant API as /v1/decide
    participant E as DecisionEngine
    participant B as ApprovalBridge
    participant S as Store
    Ag->>API: decide + approval (request, artifact, approver receipt)
    API->>E: process(action, approval, approval_context)
    E->>E: ladder says REQUIRE_APPROVAL
    E->>B: consider(...)
    B->>B: verify against the pinned approver trust bundle
    B->>B: same action digest, organisation, subject agent
    B->>B: approver is not the agent and not the caller
    B->>S: claim the approval artifact once
    alt every check holds
        B-->>E: admit
        E-->>API: ALLOW, approval_ref = artifact digest
    else any check fails
        B-->>E: refusal reason
        E-->>API: verdict unchanged
    end
```

| Step | Code |
|---|---|
| Engine hands the approval to the bridge | `agent_dna/decision.py::DecisionEngine._apply_approval` |
| All checks | `agent_dna/approval_bridge.py::ApprovalBridge.consider` |
| Single-use claim | `agent_dna/sqlite_store.py::SQLiteDecisionStore.try_consume_approval` |

An approval never overrides BLOCK and is never consumed by a decision that
was already ALLOW.

## Authorize: minting a permit

`api/server.py::authorize` refuses unless every step passes, in this order:

```mermaid
flowchart TD
  A[POST /v1/authorize] --> B{key owns agent?}
  B -- no --> X1[403]
  B -- yes --> C{stored, sealed, bound ALLOW<br/>for this record hash?}
  C -- no --> X2[refuse]
  C -- yes --> D{approval digest matches<br/>the record?}
  D -- no --> X3[refuse]
  D -- yes --> E{grant revoked?}
  E -- yes --> X4[refuse]
  E -- no --> F{signer loaded and<br/>organisation matches?}
  F -- no --> X5[403 / 503]
  F -- yes --> G{loop gate: required<br/>security events present?}
  G -- no --> X6[422]
  G -- yes --> T{approval, grant and decision<br/>window still valid?}
  T -- no / unknown --> X7[403]
  T -- yes --> H[resolve presenter key,<br/>compute bindings digest,<br/>cap expiry at the earliest end]
  H --> I[claim the mint row,<br/>sign inside the claim]
  I --> J{grant revoked<br/>while minting?}
  J -- yes --> K[suspend the new permit, refuse]
  J -- no --> L[200: signed permit]
```

| Step | Code |
|---|---|
| Sealed ALLOW lookup | `api/server.py::_require_sealed_allow_for_authorize` |
| Revoked grant | `api/server.py::_revoked_grant_for` |
| Signer (local seed or KMS) | `api/server.py::_pv_load_signer` |
| Authority still valid; permit expiry capped (ADR 0024) | `agent_dna/authority_deadline.py::authority_deadline` |
| Presenter key for mTLS (ADR 0022) | `api/server.py::_resolve_presenter` |
| What the permit binds | `agent_dna/authorize_binding.py::mint_bindings_digest` |
| One live permit per decision (ADR 0016) | `agent_dna/sqlite_store.py::SQLiteDecisionStore.claim_or_replay_mint`, `agent_dna/pg_store.py::PostgresDecisionStore.claim_or_replay_mint` |

A repeat call with the same bindings returns the same permit; a call with
different bindings for the same decision is refused.

## Dispatch: the exact-byte sidecar

`agent_dna/connector/adapters/exact_byte_http.py::ExactByteHttpDispatcher.dispatch`.
Order is fixed and fails closed; nothing goes on the wire until the permit
has verified and been consumed.

```mermaid
sequenceDiagram
    autonumber
    participant Ag as Agent
    participant SC as ExactByteHttpDispatcher
    participant L as Store (consume ledger)
    participant T as TLS transport
    Ag->>SC: dispatch(bytes, permit)
    SC->>SC: freeze the buffer
    SC->>SC: verify permit offline against the pinned trust bundle
    SC->>T: open a per-dispatch TLS session
    SC->>SC: observed peer certificate matches the permit
    SC->>L: consume permit unless suspended (one transaction)
    alt suspended or already consumed
        L-->>SC: refused
        SC-->>Ag: NOT_SENT (permit not burned if suspended)
    else consumed
        SC->>T: send the same bytes object
        SC->>SC: sign dispatch witness (observed_at)
        T-->>SC: response
        SC->>SC: sign closure (status, closed_at)
        SC-->>Ag: EXECUTED, or INDETERMINATE (never retried)
    end
```

| Step | Code |
|---|---|
| Frozen dispatch | `agent_dna/connector/adapters/exact_byte_http.py::ExactByteHttpDispatcher._dispatch_frozen` |
| Pinned verification | `agent_dna/connector/adapters/exact_byte_http.py::ExactByteHttpDispatcher._verify_pinned` |
| Consume unless suspended | `agent_dna/connector/adapters/exact_byte_http.py::ExactByteHttpDispatcher._consume`, `agent_dna/sqlite_store.py::SQLiteDecisionStore.try_consume_unless_suspended` |
| Send and witness | `agent_dna/connector/adapters/exact_byte_http.py::ExactByteHttpDispatcher._transmit_and_attest`, `agent_dna/connector/adapters/exact_byte_http.py::ExactByteHttpDispatcher._attest_after_send` |
| Closure | `agent_dna/connector/adapters/exact_byte_http.py::ExactByteHttpDispatcher._sign_closure` |
| Trust bundle rules (witness key may not also mint, ADR 0009) | `agent_dna/connector/adapters/execution_trust.py::validate_execution_trust_bundle` |

The sidecar is a control on the agent's side of the wire. An agent that holds
the upstream credentials and calls the API directly never meets it; that is
what the receiver gate is for.

## Receiver gate (ADR 0019)

Runs at the system of record, operated by its owner.
`agent_dna/receiver/gate.py::ReceiverGate.check` admits a request only if the
permit it carries verifies offline and binds what actually arrived:

```mermaid
flowchart TD
  R[request arrives] --> S{body within bound?}
  S -- no --> N[refuse + signed receipt]
  S -- yes --> P[read permit header]
  P --> T{signed by a pinned<br/>execution_authorization_signer?}
  T -- no --> N
  T -- yes --> Q{mTLS client key is the<br/>permit's presenter?}
  Q -- no --> N
  Q -- yes --> D{this receiver and destination,<br/>METHOD path exact?}
  D -- no --> N
  D -- yes --> W{inside not_before .. expires_at?}
  W -- no --> N
  W -- yes --> V{not on a fresh revocation list?}
  V -- no --> N
  V -- yes --> B{body digest and length match;<br/>body equals signed parameters?}
  B -- no --> N
  B -- yes --> O{operator local checks pass?}
  O -- no --> N
  O -- yes --> C{claim once in the receiver ledger}
  C -- already used --> N
  C -- claimed --> F[forward upstream + signed receipt]
```

| Step | Code |
|---|---|
| Ordered checks | `agent_dna/receiver/gate.py::ReceiverGate._verify` |
| Permit header | `agent_dna/receiver/gate.py::ReceiverGate._permit_from_headers` |
| Signature and pinned key | `agent_dna/receiver/gate.py::ReceiverGate._verify_trust` |
| Presenter (mTLS) | `agent_dna/receiver/gate.py::ReceiverGate._verify_presenter` |
| Revocation list | `agent_dna/receiver/gate.py::ReceiverGate._verify_not_revoked` |
| Single-use claim and receipt | `agent_dna/receiver/gate.py::ReceiverGate._admit`, `agent_dna/receiver/ledger.py::ReceiverLedger.record` |
| HTTP server around the gate | `network/receiver_kit/app.py` |

A wrong presenter is refused before the ledger, so the permit is not burned.
Every evaluated request, admitted or refused, gets a signed, hash-chained
receipt. The gate protects only operations routed through it; coverage is a
deployment property.

## Outcome

`api/server.py::outcome` checks the caller owns the decision, refuses
`status=ok` without `dispatched=true`, then appends an execution event to the
same chain (`agent_dna/decision_recorder.py::DecisionRecorder.report_outcome`).
A BLOCKed decision that the executor reports as executed anyway shows up
in `GET /v1/divergent`.

## Grant revocation

```mermaid
sequenceDiagram
    autonumber
    participant Op as Operator (pv CLI)
    participant GR as GrantRevocationLedger
    participant S as Store
    participant API as Decision API
    participant RG as Receiver gate
    Op->>GR: pv grants revoke GRANT --by --reason
    GR->>GR: commit the revocation row first
    GR->>S: suspend every permit minted under the grant
    Note over API: decide: grant no longer authorises<br/>authorize: refuses, re-checks after the mint claim<br/>dispatch: suspended permits are never sent
    RG->>API: GET /v1/revocations (signed list)
    API-->>RG: list with next_update
    Note over RG: listed permit, suspended agent or<br/>organisation: refused. Stale list: refuse all.
```

| Step | Code |
|---|---|
| CLI | `agent_dna/cli.py::cmd_grants_revoke`, `agent_dna/cli.py::cmd_grants_revoked` |
| Revoke and suspend | `agent_dna/grant_revocation.py::GrantRevocationLedger.revoke`, `agent_dna/pg_store.py::PostgresGrantRevocationLedger.revoke` |
| Signed list | `agent_dna/revocation_list.py::build_revocation_list` |
| Receiver's copy (no rollback, fails closed when stale) | `agent_dna/revocation_list.py::RevocationListCache.update`, `agent_dna/revocation_list.py::RevocationListCache.refresh` |

The CLI needs the database, never an agent API key. Actions dispatched before
the revocation committed are not reversed.

## Inline MCP gateway

`python -m agent_dna.gateway` sits between an MCP client and an MCP server.
For each tools/call request it decides, freezes the arguments, forwards only the
frozen bytes, and reports the outcome.

```mermaid
sequenceDiagram
    autonumber
    participant Cl as MCP client (agent)
    participant G as GatewayMediator
    participant API as Decision runtime
    participant Up as MCP server
    Cl->>G: tools/call
    G->>G: framing, size and depth limits, declared tool?
    G->>API: decide (via ConnectorMiddleware)
    alt allow
        G->>Up: forward the frozen request
        Up-->>G: result
        G->>API: outcome
        G-->>Cl: result
    else approval or block
        G-->>Cl: MCP error (approval / denied)
    end
```

| Step | Code |
|---|---|
| Message dispatch | `agent_dna/gateway/mediator.py::GatewayMediator.handle_message` |
| Decide and freeze | `agent_dna/gateway/mediator.py::GatewayMediator.prepare_tools_call` |
| Forward | `agent_dna/gateway/mediator.py::GatewayMediator.forward_pending` |
| Decide and outcome client | `agent_dna/connector/middleware.py::ConnectorMiddleware` |

Redirects, sampling requests, undeclared tools, mutated arguments and a
changed upstream principal are refused.

## Audit connector

`python -m agent_dna.audit_connector` is a read-only MCP server (OAuth in
front) that lets an auditor, for example Claude, query the decision API with
an audit key.

| Tool | Code |
|---|---|
| Blocked actions | `agent_dna/audit_connector/server.py::AuditTools.list_blocked_actions` |
| One agent's actions | `agent_dna/audit_connector/server.py::AuditTools.list_agent_actions` |
| One decision | `agent_dna/audit_connector/server.py::AuditTools.get_decision` |
| Verify the trail | `agent_dna/audit_connector/server.py::AuditTools.verify_audit_trail` |
| Activity summary | `agent_dna/audit_connector/server.py::AuditTools.activity_summary` |
| Revocations | `agent_dna/audit_connector/server.py::AuditTools.list_revocations` |
| Server with OAuth | `agent_dna/audit_connector/server.py::build_oauth_server` |

## Offline verification

Anyone with the exported files and the public keys can check them. The
verifiers use the standard library only and never import `agent_dna`.

| What | Tool |
|---|---|
| Decision records and envelopes | `tools/verify_records.py` |
| Receiver receipts | `tools/verify_receiver_receipts.py` |
| Lineage events | `tools/verify_lineage.py` |
| A running deployment's posture | `tools/verify_deployment.py` |

The offline verifier proves integrity and server-key attestation, not
independent approval; it needs trusted keys and identity bindings.

## Backup and restore

```mermaid
sequenceDiagram
    autonumber
    participant Op as Operator
    participant BK as agent_dna.backup
    participant DB as Ledger database
    participant T as Empty target
    Op->>BK: backup --out DIR --signing-key KEY
    BK->>DB: export one snapshot
    BK->>DB: dump and fingerprint the same snapshot
    BK->>BK: write manifest (row counts, digests), sign it
    Op->>BK: restore DIR --public-key KEY
    BK->>BK: verify dump digest and manifest signature
    BK->>T: load (target must be empty)
    BK->>T: fingerprint again, verify every chain
    BK-->>Op: verified, or failed
```

| Step | Code |
|---|---|
| SQLite | `agent_dna/backup.py::backup_sqlite` |
| PostgreSQL | `agent_dna/backup.py::backup_postgres` |
| Check a backup | `agent_dna/backup.py::verify_backup` |
| Restore and prove | `agent_dna/backup.py::restore` |

Runbook: [../operations/BACKUP.md](../operations/BACKUP.md).
