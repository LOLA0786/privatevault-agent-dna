# Agentic Trust Controls — Mapping

Self-assessment against Vanta's Agentic Trust Controls (Developer
baseline), same honesty discipline as this project's AARM Core
mapping: every PASS traces to a real, named test file. Every FAIL or
PARTIAL is stated plainly, not hedged. Only Developer-baseline
controls are assessed here — User-baseline controls are the
deploying organization's operational responsibility, not something a
runtime's code can satisfy on its own.

Status legend: **PASS** (tested, shipped) · **PARTIAL** (a real but
narrower mechanism exists) · **FAIL** (not built).

---

## AID — Agent Identity & Authority

| Control | Status | Evidence |
|---|---|---|
| AID-01 Verifiable agent identity | **PASS** | Every `DecisionRecord` is bound to `agent_id` within a per-agent hash chain (`agent_dna/decision_record.py`, `tests/test_decision_record.py`) |
| AID-02 Rotatable credentials, disposable state | **PARTIAL** | API keys are hash-based and can be regenerated/replaced in the key file (`agent_dna/apikeys.py`), but there is no live revoke-without-restart mechanism, and there is no persistent agent memory/context store for this runtime to dispose of |
| AID-03 Least-privilege tool scoping | **PASS** | Capability grants (precedence level: authorization) enforce per-capability, per-agent access with expiry and budget (`agent_dna/grants.py`, `tests/test_capability_grants.py`) |
| AID-04 Just-in-time privilege | **FAIL** | Grants are static once issued; no time-scoped or task-scoped JIT issuance mechanism exists |
| AID-05 Authority attestation at execution | **PASS** | Every decision record binds action, agent identity, the deciding precedence level (`triggered_by`), and the reason at the moment of decision, sealed and optionally signed (`agent_dna/decision_record.py`, `agent_dna/signer.py`) |

## TUE — Tool Use & Action Execution

| Control | Status | Evidence |
|---|---|---|
| TUE-01 Deterministic tool guardrails | **PASS** | The entire precedence engine: eight-level deterministic-first evaluation, hash-pinned and CI-guarded (`agent_dna/decision.py`, `spec/contracts/precedence-order.json`, `tests/test_precedence_contract.py`) |
| TUE-02 Tool allowlisting/denylisting | **PASS** | Capability grants define exactly which capabilities an agent may invoke; ungranted capabilities require approval (`agent_dna/grants.py`) |
| TUE-03 Parameter validation before execution | **PASS** | L0 evidence-checked predicates validate action parameters against enterprise state before execution (`agent_dna/uaal_layer.py`) |
| TUE-04 Tool execution sandboxing | **FAIL** | Out of scope by design — this runtime decides whether an action may proceed; it does not execute the tool call or provide sandboxing |
| TUE-05 Circuit-breaker/kill-switch | **FAIL** | Economics (L4) flags individual-action cost anomalies but there is no rate/volume/recursion threshold that automatically suspends an agent |

## RII — Reasoning & Instruction Integrity

| Control | Status | Evidence |
|---|---|---|
| RII-01 Data/instruction separation | **PARTIAL** | L0's identity-preservation check compares canonical target across user request, planner, and tool call — a narrow, specific defense against instruction/target confusion, not a general content-trust-labeling system |
| RII-02 Input/tool-output provenance labeling | **FAIL** | Not built |
| RII-03 Prompt-injection resistance testing | **PARTIAL** | The adversarial corpus (`spec/adversarial/attack_corpus.py`) includes target-redirection scenarios consistent with injection defense, but this is self-authored, not independent red-teaming, and not run on a recurring cadence |
| RII-04 Goal-integrity/drift detection | **PASS** | Learned behavioral drift (precedence level: drift) detects deviation from an agent's established capability/transition baseline (`agent_dna/scorer.py`, `agent_dna/dynamics.py`) |

## MEM — Memory & State Integrity

Not applicable in the traditional sense — this runtime has no
persistent agent memory or retrieval store; it evaluates individual
proposed actions. **FAIL/N-A** across MEM-01 through MEM-03.

## MAS — Multi-Agent Systems & Delegation

| Control | Status | Evidence |
|---|---|---|
| MAS-01 Inter-agent authentication | **PASS** | HMAC-signed votes in `SecureQuorum`; forged signatures proven rejected (`agent_dna/consensus/secure_quorum.py`, `tests/test_secure_quorum.py`) |
| MAS-02 Agent communication integrity | **PASS** | Same mechanism — signed votes carry authentication sufficient to validate source before the vote is counted |
| MAS-03 Delegation-chain authority propagation | **FAIL** | No delegation chain mechanism; a named, stated roadmap gap (`docs/WHAT-WE-DO-NOT-CLAIM.md`) |
| MAS-04 Sub-agent inventory/discovery | **FAIL** | Not applicable/not built — no sub-agent spawning concept in this runtime |

## HOA — Human Oversight Under Autonomy

| Control | Status | Evidence |
|---|---|---|
| HOA-02 Risk-tiered autonomy | **PASS** | The precedence model itself is risk-tiered: deterministic violations BLOCK, softer signals (grants, economics, consensus, drift) REQUIRE_APPROVAL, routing to human review |
| HOA-03 Escalation criteria for autonomous action | **PASS** | Every REQUIRE_APPROVAL outcome is a documented, deterministic escalation trigger, not an ad hoc judgment call |
| HOA-01 Oversight-load management | **FAIL** | No mechanism to manage reviewer volume/pacing |

## RBM — Runtime Behavioral Monitoring

The strongest domain in this assessment.

| Control | Status | Evidence |
|---|---|---|
| RBM-01 Behavioral telemetry generation | **PASS** | Every decision is a structured, queryable record (`agent_dna/decision_graph.py`) |
| RBM-02 Behavioral drift detection | **PASS** | Same as RII-04 above |
| RBM-03 Tamper-evident action logging | **PASS** | Hash-chained, Ed25519-signed records; independent stdlib-only verifier catches field tampering, chain breaks, forged results, deletion, and enforcement divergence (`tools/verify_records.py`, four canonical test vectors, `tests/test_spec_vectors.py`) |
| RBM-04 Instrumentation for external enforcement | **PASS** | HTTP API (status-code-as-signal) and MCP tool surface (`api/server.py`, `agent_dna/mcp_server.py`) |

## SCP — Supply Chain & Component Provenance

| Control | Status | Evidence |
|---|---|---|
| SCP-05 Tool/MCP definition integrity, pinning, typosquat protection | **FAIL** | Real, newly-identified gap — the MCP server does not pin or re-verify its own tool definitions at load time |
| SCP-01/02/03 | **FAIL** | Not built |

## ADV — Adversarial Robustness & Testing

| Control | Status | Evidence |
|---|---|---|
| ADV-01 Adversarial red-teaming | **PARTIAL** | 11-scenario adversarial corpus exists, explicitly built to be extended and re-run by an external reviewer, not just self-graded (`spec/adversarial/attack_corpus.py`) — but no independent third-party red-team exercise has actually been performed |
| ADV-03 Re-test on system change | **PASS** | CI runs the full test suite and spec vectors on every push (`.github/workflows/`) |

## OUT — Output Integrity & Anti-Fabrication

Not directly applicable — this runtime does not generate agent
outputs; it evaluates proposed actions. **N-A** across OUT-01–03.

## RES — Resource & Cost Abuse

| Control | Status | Evidence |
|---|---|---|
| RES-01 Action/cost rate limiting | **PARTIAL** | Economics level (L4) detects cost-ratio anomalies and ROI-floor violations per action, but has no rate/volume window and does not itself throttle |
| RES-02 Loop/recursion bounds | **FAIL** | Not applicable at this layer — no reasoning loop exists in this runtime to bound |

---

## Summary

**Strongest domains:** TUE (deterministic guardrails), RBM (tamper-evident logging, drift detection), MAS (signed inter-agent authentication) — these map almost directly onto what this sprint built and tested.

**Real, named gaps, in priority order for a future session:**
1. SCP-05 — MCP tool definition pinning/re-verification (small, scoped, newly identified here)
2. TUE-05 — circuit-breaker/rate-based kill-switch (real, not yet designed)
3. AID-04 — just-in-time, task-scoped privilege (grants are currently static)
4. MAS-03 — delegation-chain authority propagation (already a named roadmap item)
5. ADV-01 — genuine independent red-teaming, as distinct from the self-built adversarial corpus

**Not applicable by design:** MEM, OUT, TUE-04 (sandboxing), RES-02 — this runtime is a pre-execution decision layer, not an agent memory system, output generator, sandbox, or reasoning loop, and does not claim to be.
