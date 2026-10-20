# Enterprise readiness: what a security review will ask, and the answer today

Written 2026-10-19 against master `651ad58` plus the `harden/enterprise`
changes. Every "Shipped" row names files that exist in this repository
(`tests/test_compliance_paths.py` fails if one is removed). "Not started"
means no code. Effort is engineering time for one experienced engineer.

| Area | Status | Where (verified) | Open |
|---|---|---|---|
| Fail-closed decisions | Shipped | `tests/test_fail_closed.py`, `tests/test_api_fail_closed.py`, `tests/test_auth_fail_closed.py` | none known |
| HA on one PostgreSQL | Shipped (correctness) | `tests/multi_instance/test_two_processes.py`, `deploy/helm/privatevault/values.yaml` (2 replicas, PDB, HPA) | no multi-host load or failover test; receiver ledger SQLite only |
| Signing keys in KMS | Shipped (AWS, GCP) | `agent_dna/key_custody.py`, `tests/test_key_custody.py`, `docs/adr/0023-signing-keys-in-kms.md` | no HSM/PKCS#11, Azure Key Vault or Vault Transit; not run against a live KMS in-cluster |
| Signing-key rotation | Partial | `agent_dna/key_lifecycle.py`, `tests/test_key_lifecycle.py`, `tests/test_key_rotation_provisioned.py` | no scheduled rotation, no API-key hot reload, trust-bundle rollover is manual |
| Human approvals | Partial | `agent_dna/approval_bridge.py`, `docs/adr/0020-approval-bridge.md` | one pinned approver; no quorum, roles, SSO/OIDC/SAML or SCIM |
| Multi-tenancy | Not started | `agent_dna/apikeys.py` ("no tenants") | one deployment per organisation |
| Audit export / SIEM | Shipped | `GET /v1/audit/export` in `api/server.py`; `tools/siem_export.py` (ECS NDJSON, CEF), `tests/test_siem_export.py` | no push connector (syslog/HEC/Kafka); scheduled pull with `--after` |
| Rate limiting / DoS | Shipped (per process) | `agent_dna/rate_limit.py`, `tests/test_rate_limit.py`, `agent_dna/request_bounds.py`, `tests/test_request_bounds.py` | only registered API keys get their own bucket; unknown or absent keys share their client address's; per-replica buckets, no shared limiter |
| Shell guard: content secrets, destructive scripts, TOCTOU | Shipped (same host) | `agent_dna/shell_guard.py`, `agent_dna/shell_pin.py`, `tests/test_shell_guard_hardening.py`, `tests/test_shell_guard_confinement.py` | needs `PV_SHELL_WORKDIR` and reads only inside it; `run_pinned` runs only a sealed ALLOW's exact arguments; static analysis, not a sandbox |
| Supply chain | Partial | `uv.lock`, `.github/dependabot.yml`, `.github/workflows/codeql.yml`, `.github/workflows/ci.yml` (pip-audit gate, SBOM), `.github/workflows/release.yml` (provenance, cosign), `rust/deny.toml` | release workflow never run. Base images are digest-pinned (`tests/test_image_pins.py`; the dashboard's node/nginx images are listed there as not yet pinned). Every GitHub Action is pinned to a commit SHA (`tests/test_workflow_pins.py`), kept current by Dependabot |
| Threat model | Shipped | `docs/THREAT-MODEL.md`, `docs/SECURITY.md` | no STRIDE/data-flow diagram per trust boundary |
| Pen test | Not started | `docs/PRODUCTION-HARDENING.md` | external test needed |
| SOC 2 / ISO 27001 | Not started (mapping only) | `docs/compliance/soc2/control_mapping.md` | organisational controls, auditor |
| India: CERT-In / RBI | Partial (deployment-dependent) | self-hosted in the customer's environment (`Dockerfile`, `deploy/helm/privatevault/Chart.yaml`) | 180-day log retention in India and NTP sync are the operator's; no residency enforcement in shipped code (`docs/GLOBAL_DEPLOYMENT.md` is experimental) |
| Observability | Partial | `agent_dna/observability/metrics.py`, `agent_dna/observability/logger.py`, `tests/test_metrics_endpoint.py` | no tracing, no alert rules |
| Versioning / upgrade | Partial | `CHANGELOG.md`, `docs/SECURITY-MIGRATION-v0.5.md`, `docs/RELEASE-CHECKLIST.md` | no published support window or schema-migration tool |

The full analysis, with effort and priority per row, is kept outside the
repository with the review that produced it.
