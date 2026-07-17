# SOC 2 Type II — Control Mapping to PrivateVault Agent DNA (v0.2.0)

Audit reference: Commit 4cc19b3 (Byzantine PBFT + Adapter Layer)
Scope: Agent governance runtime, decision audit, multi-agent consensus

## Trust Services Criteria (TSC) Mapping

### Security (CC6.x) — Logical & Physical Access
| Code File | Control Evidence |
|---|---|
| `agent_dna/auth/` | RBAC enforcement |
| `agent_dna/authorization.py` | Capability grants (`CapabilityGrant`) |
| `agent_dna/grants.py` | Agent-to-capability authorization registry |
| `agent_dna/uaal_layer.py` | Enterprise constraint checks (L0) |

### Availability (CC7.x) — System Operations
| Code File | Control Evidence |
|---|---|
| `agent_dna/runtime.py` | `RuntimeMonitor` — live enforcement stream |
| `agent_dna/circuit_breaker.py` | Pre-gate suspension (fail-closed) |
| `agent_dna/consensus/byzantine.py` | PBFT consensus (3f+1, 30s expiry) |
| `agent_dna/observability/metrics.py` | Metrics exporter (`MetricsExporter`) |

### Processing Integrity (CC8.x) — Change Management & Audit
| Code File | Control Evidence |
|---|---|
| `agent_dna/decision.py` | `DecisionEngine` — deterministic precedence (L0-L6) |
| `agent_dna/decision_record.py` | Tamper-evident decision record |
| `agent_dna/signer.py` | Ed25519 signatures (`ReceiptSigner`, `rotate_key`) |
| `agent_dna/consensus/signing.py` | HMAC-SHA256 vote verification (`compare_digest`) |
| `agent_dna/adapters_policy/` | Policy adapter layer (local/git/OPA) — no rewrite required |

### Confidentiality (CC6.x) — Data Protection
| Code File | Control Evidence |
|---|---|
| `docs/SECURITY.md` | Security model document |
| `agent_dna/signer.py` | Key rotation stub (`rotate_key`) |
| `agent_dna/consensus/byzantine.py` | Time-bound vote expiry (replay prevention) |
| `pyproject.toml` | Dependency pinning (`cryptography>=43.0`, `pydantic>=2.9.0`) |

## Evidence Artifacts (Audit Package)
- `agent_dna/observability/logger.py` — Structured JSON logs with `timestamp`, `agent_id`, `verdict`
- `agent_dna/observability/metrics.py` — Verdict distribution (`ALLOW`, `BLOCK`, `REQUIRE_APPROVAL`)
- `agent_dna/consensus/byzantine.py` — Audit summary (`audit_summary`) with `prev_decision_hash`
- `docs/SECURITY.md` — Threat model, constant-time verification, fail-closed behavior

## Non-Applicable / Exceptions
- FedRAMP High: Not yet certified (planned Q3)
- FIPS 140-3: Cryptographic module (`nacl`) requires validation (planned)
- Multi-region PostgreSQL: Adapter exists (`adapters_policy/`); cluster deployment planned

## Auditor Notes
Every `BLOCK` or `REQUIRE_APPROVAL` verdict produces:
1. A `DecisionRecord` (`agent_dna/decision_record.py`)
2. An Ed25519 `SignatureEnvelope` (`agent_dna/signer.py`)
3. A chain-linked hash (`prev_decision_hash`) in consensus votes (`byzantine.py`)
4. A JSON log entry (`agent_dna/observability/logger.py`)

This creates independent, cryptographic proof of enforcement — admissible as audit evidence, not just system logs.
