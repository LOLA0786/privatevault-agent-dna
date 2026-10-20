# SOC 2 Type II — Control Mapping to PrivateVault Agent DNA (v0.4.0)

**Audit Reference:** Commit 4cc19b3 (Byzantine PBFT + Adapter Layer). Paths re-checked 2026-10-19; every path below must exist (`tests/test_compliance_paths.py`). For ISO 27001, RBI and CERT-In see `docs/ENTERPRISE-READINESS.md`.

**Scope:** Agent governance runtime, decision audit, multi-agent consensus

---

# Trust Services Criteria (TSC) Mapping

## CC6 — Logical Access & Security

| Control | Implementation | Evidence File |
|----------|----------------|---------------|
| CC6.1 — Logical access security | Hashed API keys with full/audit scopes; per-agent capability grants (no human-user RBAC or SSO yet, see `docs/ENTERPRISE-READINESS.md`) | `agent_dna/apikeys.py`, `agent_dna/grants.py`, `agent_dna/authorization.py` |
| CC6.2 — Access removal | Profile revocation via grants | `agent_dna/grants.py` |
| CC6.3 — Security infrastructure | Enterprise constraints (UAAL Layer) | `agent_dna/uaal_layer.py` |

---

## CC7 — System Operations & Monitoring

| Control | Implementation | Evidence File |
|----------|----------------|---------------|
| CC7.1 — Runtime monitoring | RuntimeMonitor event stream | `agent_dna/runtime.py` |
| CC7.2 — Monitoring tools | Metrics exporter & structured logging | `agent_dna/observability/` |
| CC7.3 — Incident detection | Circuit breaker | `agent_dna/circuit_breaker.py` |

---

## CC8 — Change Management & Processing Integrity

| Control | Implementation | Evidence File |
|----------|----------------|---------------|
| CC8.1 — Change authorization | Policy adapter layer | `agent_dna/adapters_framework/` |
| CC8.2 — Secure development | Version-controlled source | `pyproject.toml`, `docs/SECURITY.md` |
| CC8.3 — Deterministic policy evaluation | Decision engine precedence | `agent_dna/decision.py` |

---

## Audit & Non-Repudiation

| Requirement | Implementation | Evidence File |
|-------------|----------------|---------------|
| Decision receipts | Signed decision records | `agent_dna/decision_record.py` |
| Cryptographic signing | Ed25519 signatures | `agent_dna/signer.py` |
| Immutable audit evidence | Hash-chained, signed decision ledger; independent verifier | `agent_dna/sqlite_store.py`, `agent_dna/pg_store.py`, `tools/verify_records.py` |
| Execution history | Timeline & execution records | `agent_dna/timeline.py`, `agent_dna/execution_record.py` |
| Multi-agent consensus | Byzantine PBFT | `agent_dna/consensus/` |

---

## Evidence Collection

The following artifacts should be retained for a SOC 2 Type II audit:

- Git commit history
- Signed decision receipts
- Runtime audit logs
- Policy configuration history
- Consensus event logs
- Authorization records
- Change management records
- Incident response logs
