# PrivateVault Discovery Loop

PrivateVault's Discovery Loop is an offline, low-compute experimental system
for improving decision-security controls. It follows the scientific cycle:

`propose -> run -> evaluate -> iterate`

The similarly named **agent security loop detector** is a different component.
That detector analyzes cross-agent authority, replay, and causal cycles. The
Discovery Loop can consume its report as one structural probe.

## What one run does

| Phase | PrivateVault implementation | Security boundary |
|---|---|---|
| Propose | `policy_miner` derives policy, grant, and advisory candidates from verified sealed decisions | Every candidate includes the complete motivating record hashes |
| Run | Assertions plus additive replay over retained history and a committed adversarial JSONL corpus | Candidate non-fire leaves the existing L0-L7 result unchanged |
| Evaluate | Divergence budget, corpus coverage/preservation with Wilson intervals, loop probe, optional `pv-validation/1` summary | Candidate errors and structural `BLOCK` reject; structural `REVIEW` prevents proposal |
| Iterate | Deterministic ranking and PR-ready policy/review files | Nothing is installed; a named human still owns review and merge |

The pipeline uses counts, comparisons, deterministic policy evaluation, and
closed-form statistics. It makes no model or network calls. Models may help
author future synthetic fixtures, but model output is never evidence or
authorization.

## Run it

```bash
pv discover run \
  --history-db decisions.db \
  --replay-db decisions.db.replay.db \
  --replay-fields amount \
  --adversarial-fixture examples/discovery_loop/adversarial.jsonl \
  --loop-events events.jsonl \
  --validation-report validation.json \
  --max-new-blocks 0 \
  --json discovery-report.json \
  --out-dir discovery-proposals

python tools/verify_discovery.py discovery-report.json
```

Replay inputs are opt-in and field-scoped. The immutable decision store keeps
digests, not raw arguments; the separate replay sidecar is required for
conditional counterfactuals. A missing field makes that experiment incomplete
and cannot produce `PROPOSE`.

## Dispositions

| Disposition | Meaning |
|---|---|
| `PROPOSE` | Assertions, complete additive history replay, committed adversarial replay, budgets, and structural filters passed. Ready to become a human-reviewed PR. |
| `REVIEW` | Evidence is incomplete or a structural probe requires judgment. |
| `REJECT` | Deterministic check, divergence budget, candidate evaluation, or structural block failed. |
| `ADVISORY` | The mined pattern is not expressible as an additive policy rule, such as a sequence or grant-design issue. |

The priority score is a stable triage heuristic. It is not a probability,
validation metric, or authorization decision. Wilson intervals characterize
only the committed adversarial corpus; they do not turn synthetic labels into
independent ground truth.

## Integrity and isolation

- `run_discovery` verifies the entire decision graph before mining.
- Reports bind normalized input identity and candidates with SHA-256 digests.
- `tools/verify_discovery.py` checks the report using only the Python standard
  library and does not import the producing runtime.
- Generated proposal notes carry the report digest, candidate digest, and full
  motivating record hashes.
- Online enforcement does not import or call the discovery runner. L0-L5 stay
  deterministic, L6 stays advisory-only, and L7 remains the baseline allow.
- Hodge and authority-reachability experiments remain quarantined and cannot
  gate proposals until stable schemas and independent verifiers ship.

## CI pattern

Treat the corpus, configuration, and emitted report as reviewed artifacts.
Verify the report independently, inspect every `PROPOSE` note, and run the
normal `pv policy check` gate again on the actual PR. Never auto-merge or
auto-deploy a discovered policy.
