# Phase 1 pre-change map (PV-001)

**Worktree:** `.worktrees/pv001`  
**Branch:** `security/remediation-pv001`  
**Base:** `master` @ `c63b75f468490414bfd1936c69d9a2d28e7ac58d`  
**Dirty tree preserved:** `fix/caller-controlled-enforcement` @ `9ab660f` (untouched)

## Where DRP 0.1 reaches permit minting today

```text
POST /v1/decide
  → RuntimeMonitor.process
  → DecisionRecorder.record
       → build_record(...)          ## ALWAYS emits drp/0.1, action_digest=None
       → SQLite append
  → response.record (drp/0.1)

POST /v1/authorize
  → _require_sealed_allow_for_authorize
       → bind_authorize_to_sealed_allow
            checks: ALLOW, agent, receipt, capability, arguments_digest
            action_digest: OPTIONAL (only if present on record)
            protocol_version: NOT checked
            dispatch: NOT sealed / NOT compared to decide
  → sign_execution_authorization(caller action + caller dispatch + digests)
  → 200 + permit
```

**Bypass:** Preserve capability + parameters; change subject_principal / subject_key_id / resource / destination / operation / content-type → mint still succeeds.

## Plan vs repository (no contradiction found)

| Plan assumption | Repo evidence |
|---|---|
| `build_record_v02` exists, derive-only | `decision_record.py:309-334` uses `execution_action_digest` |
| Recorder still calls `build_record` | `decision_recorder.py:101`, `:161` |
| `action_v01` is five fields | `EXECUTION_ACTION_FIELDS` unchanged (D1) |
| Dispatch sealed separately | Not present yet — Phase 1 adds `dispatch_context_v01` |
| Authorize optional digest check | `authorize_binding.py:102-111` |
| Exact-wire not Phase 1 | Confirmed; wire digests remain EA-only |

## Implementation targets

1. `agent_dna/dispatch_context_v01.py` — versioned derive-only digest  
2. `decision_record.py` — DRP 0.2 seals `action_digest` + `dispatch_context_digest`  
3. `decision_recorder.py` — mintable path uses `build_record_v02`  
4. `authorize_binding.py` — refuse DRP 0.1; recompute both digests with `hmac.compare_digest`  
5. `api/server.py` — decide requires execution_action + dispatch_context; authorize passes dispatch  
6. Adversarial tests — field mutation matrix  
7. `docs/SECURITY-MIGRATION-v0.5.md` — compatibility break  
