# Security migration notes — DRP 0.2 mintable decisions (Phase 1 / PV-001)

## Compatibility break

Mintable decisions are now **DRP 0.2** only.

| Surface | Before | After |
|---|---|---|
| `POST /v1/decide` (API) | Sealed `drp/0.1` without action/dispatch digests | Accepts `execution_action` + `dispatch_context` for a mintable DRP 0.2 record with derive-only `action_digest` and `dispatch_context_digest`. Both omitted still seals an audit-only DRP 0.1 record. Exactly one supplied is refused (422) |
| Connector middleware | Sealed `drp/0.1` | Seals DRP 0.2 with derived digests |
| `POST /v1/authorize` | Bound to ALLOW + optional `action_digest` | Refuses `drp/0.1`; independently recomputes both digests; mismatch refuses mint |
| `build_record(...)` | Default mint path | Audit-only DRP 0.1; **cannot mint permits** |
| `tools/verify_records.py` | Accepted only `drp/0.1` decision records | Accepts `drp/0.1` (no digests) and `drp/0.2` (both digests required) |

## Caller requirements

### Binding is optional; minting is not

`POST /v1/decide` has three states, matching `DecisionRecorder.record`:

| `execution_action` | `dispatch_context` | Result |
|---|---|---|
| present | present | DRP 0.2 — sealed and **mintable** |
| absent | absent | DRP 0.1 — sealed, audit-only, **cannot mint** |
| exactly one | | **422** — partial binding refused |

Existing callers that send neither continue to work unchanged and receive a
sealed decision record. They cannot mint an execution permit from it:
`/v1/authorize` refuses `drp/0.1` with `AUTHORIZE_PROTOCOL_NOT_AUTHORIZING`.

1. To mint, supply complete `execution_action` (five `action_v01` fields) and `dispatch_context` (`pv-dispatch-context/0.1` fields).
2. Do **not** send `action_digest` or `dispatch_context_digest` — caller-authored digests are refused.
3. `execution_action.action` must equal `capability`; `subject_key_id` must equal `agent_id`; `parameters` must equal `arguments`.
4. Authorize with the same action + EA dispatch that projects to the sealed dispatch context (adapter defaults from transport when omitted on EA dispatch).

## Explicit non-claims (Phase 1)

- Exact wire-byte enforcement is **not** claimed.
- Custom transports remain unprotected (reference HTTPS dispatcher is the only protected execution profile — later phases).
- Caller-provided governance digests are a Phase 2 concern (strict reject / ABSENT).
- Unlimited remints and consume-before-send are out of Phase 1 scope.

## External sync note

`tools/verify_records.py` changed. The vendored copy in the separate `drp-spec` repository must be updated in lockstep before treating public-spec parity as complete.
