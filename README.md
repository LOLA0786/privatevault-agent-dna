# PrivateVault Agent DNA™ — Behavioural Identity Core

> Identity tells you *who* an agent is. Agent DNA tells you whether the agent is
> still behaving like *itself*.

A zero-dependency Python core that learns an autonomous agent's trusted
operational profile from execution traces and emits **advisory** evidence when
the agent starts behaving unlike itself. The learned model never enforces; the
deterministic firewall does.

## Why this exists

The rest of the PrivateVault stack (Decision Integrity Engine, Trust Fabric,
Approval Binding, Replay Engine) is *deterministic* — it enforces policy and
produces tamper-evident audit. Agent DNA is the layer those don't cover:
**behavioural drift detection**. It answers a question deterministic rules
can't: "every individual action here is technically permitted — but is this
still the same agent we profiled?"

It is built from inspectable statistics (capability vocabulary, a Markov
transition model, per-argument distributions) rather than a black box, because in
BFSI/healthcare every flag must come with a one-sentence "why".

## The non-negotiable property

`advisory.py` makes the research-vision promise — *"the learned model is advisory
only and never replaces policy enforcement"* — a **code-level invariant**:

1. A deterministic policy `DENY` is final. Agent DNA can never turn it into an `ALLOW`.
2. Agent DNA can only *raise* scrutiny (escalate `ALLOW` → `require_approval`),
   never lower it.

That keeps the security boundary deterministic and auditable; the ML adds earlier
warning, not a new bypass. This is a selling point, not a limitation.

## Architecture

execution traces ──► CapabilityManifold (CML)   what's normal: vocab + arg distributions
                 └─► BehaviorDynamics  (BDM)     normal ordering: Markov transition model
                            │
                            ▼
                       DriftScorer ──► AdvisorySignal   (score + severity + reasons)
                            │
                            ▼
                     DeterministicGate ──► authoritative decision
                     (policy wins; advisory can only escalate)

| Module | Role |
|---|---|
| `trace.py` | The data contract: `AgentAction`, `ExecutionTrace`. |
| `manifold.py` | Capability Manifold Learning — vocabulary, argument feature distributions, timing. |
| `dynamics.py` | Behavior Dynamics — Laplace-smoothed Markov model over capability order. |
| `scorer.py` | Decomposed drift score (novelty / sequence / arguments) with reasons. |
| `advisory.py` | `AdvisorySignal` + `DeterministicGate` — the enforcement boundary. |
| `adapters.py` | Real-trace integration point + clearly-labelled synthetic generators. |

## Quickstart

```bash
cat <<'EOF' > /tmp/run_agent_dna.sh
cd privatevault-agent-dna
python -m pip install -e ".[dev]" --break-system-packages
python -m pytest -q
python -m examples.demo
