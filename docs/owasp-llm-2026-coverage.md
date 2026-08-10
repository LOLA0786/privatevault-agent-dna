# OWASP Top 10 for LLM Applications 2026 — PrivateVault Coverage
# Generated from named tests in privatevault-agent-dna. cbrain not yet scanned.
# Status: COVERED (tests prove it) | PARTIAL (named subset) |
#         ADJACENT (different control, same neighbourhood) | NOT COVERED

| ID    | Entry                   | Status      | Evidence / Note |
|-------|-------------------------|-------------|-----------------|
| LLM01 | Prompt Injection        | NOT COVERED | We do not prevent injection. Per OWASP's own position, no reliable prevention exists; defense is architectural. We implement LLM01 mitigation #4 — deterministic mediation at the action boundary — so a successful injection does not become a successful exploit. |
| LLM02 | Sensitive Info Disclosure | NOT COVERED | No redaction tests in this repo. Recheck cbrain. |
| LLM03 | Excessive Agency        | COVERED     | 22 tests. test_precedence_order, test_bundle_silence_cannot_authorize, test_gate_cannot_override_policy_deny, test_raising_authorizer_fails_closed, test_unauthorized_effect_no_matching_decision. |
| LLM04 | Supply Chain            | NOT COVERED | Model/adapter/corpus supply chain is out of scope. We sign decision artifacts, not model artifacts. |
| LLM05 | Data & Model Poisoning  | ADJACENT    | We detect behavioural consequence at runtime (drift, baseline integrity); we do not prevent training or corpus poisoning. |
| LLM06 | Unbounded Consumption   | PARTIAL     | Have: causal depth bounds, per-action budget, concurrent budget contention, cost-ratio anomaly, ROI floor. Missing: wall-clock limits, loop-detection state hashing, per-user rate limits, token-level accounting. |
| LLM07 | Misinformation          | PARTIAL     | Evidence integrity: COVERED (forged/misattributed evidence, self-labelled ground truth refused, cross-agent outcome reporting blocked). Model groundedness: NOT COVERED. |
| LLM08 | Hidden Context Exposure | ADJACENT    | test_verified_context_digest_mismatch_blocks binds context integrity at decision time. We do not defend against context extraction. |
| LLM09 | Vector & Embedding      | NOT COVERED | No embedding or retrieval surface. |
| LLM10 | Improper Output Handling| PARTIAL     | Tool-call argument validation before dispatch. Not browser/shell/SQL sink encoding. |

## Control category the LLM Top 10 does not enumerate
Authority provenance and execution evidence: signed, hash-chained decision
records binding an action to the policy version and authority in force at
decision time. 64 signature tests, 37 tamper-evidence tests. Mapped against
the Agentic Top 10 (ASI) in a companion document — see docs/owasp-asi-2026-coverage.md.

## Honesty is enforced in code
test_authority_cli_claim_is_honest
test_unsigned_runtime_does_not_claim_signature_verification
test_all_claim_sites_agree_with_each_other
