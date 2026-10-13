# Customised agents on PrivateVault

A config-driven agent template where every money-moving or external action
goes through PrivateVault: `/v1/decide` for the verdict, a signed human
approval for escalations (ADR 0020), `/v1/authorize` for a single-use permit,
the exact-byte sidecar for dispatch, and a receiver gate (ADR 0019) as the
last word. A new persona is a YAML file plus a tool list. Nothing here
changes core code, and nothing here is shipped in the wheel.

## Layout

| Path | What |
|---|---|
| `core/model.py` | The model is a proposer. `ScriptedModel` for tests and demos; `AnthropicModel` opt-in (`PV_AGENT_MODEL=anthropic`), never used in tests. Defaults to `claude-sonnet-5-5`; set `PV_AGENT_MODEL_NAME=claude-opus-5-5` to opt into Opus. |
| `core/tools.py` | `Tool` with a risk class. Read tools run freely; external tools need a single-use clearance; money tools never execute locally, their effect is the dispatch. |
| `core/persona.py` | Loads `persona.yaml` and compiles it to `PV_POLICY_FILE` and `PV_GRANTS_FILE`. No rule is evaluated here. |
| `core/approval.py` | `ApproverKit` signs `approval_v01` artifacts with a real authority receipt; `ScriptedApprover` and `ConsoleApprover`. |
| `core/gate.py` | `PrivateVaultGate`: decide, mint, dispatch. Holds no keys. |
| `core/transport.py` | Demo-grade sidecar transport into an in-process receiver. Says so in its docstring. |
| `core/runner.py` | The loop. Model proposes, PrivateVault decides, the runner obeys, every gated step is logged. |
| `core/receipts.py` | Append-only, hash-chained receipt log for a run. |
| `core/harness.py` | In-process assembly: API, receiver gate over the receiver kit's stub upstream (or a demo's own mock via `upstream_factory`), sidecar, approver bundle, per-run keys. |
| `personas/finance_ops/` | Persona 1. `persona.yaml`, `tools.py`, `demo.py`, `README.md`. |

## Adding a persona

1. Copy `personas/finance_ops/` and rename.
2. Edit `persona.yaml`: identity, tool names, grants, policy rules (the
   engine's rule schema: `capability`, `outcome: block | require_approval`,
   `reason`, one `condition {field, operator, value}`), approvers.
3. Write `tools.py`: `Tool` objects with a risk class; money tools name a
   `ReceiverSpec`.
4. Script a demo and tests with `ScriptedModel`. No model keys needed.

## Rules the template enforces

- The model never sees credentials and never executes anything itself.
- A money tool's arguments are what PrivateVault decides on and exactly what
  is dispatched; the permit binds those bytes.
- A refused approval never changes a verdict. BLOCK cannot be approved.
- Nothing is retried. INDETERMINATE is terminal for that step.
- The drift baseline (`PV_BASELINE_CAPABILITIES`) is the persona's declared
  tool capabilities. A capability the persona never declared is drift, and
  drift escalations cannot be approved; that is the engine's rule, kept.
