# Changelog

Claims discipline applies here too: every entry corresponds to code
and a named test that runs in CI.

## Unreleased

### Security
- **F-01 authorize binding**: `POST /v1/authorize` requires
  `decision_id` and/or `record_hash`, loads the sealed decision, refuses
  unless ALLOW, and recomputes action/arguments/receipt digests against
  the record. Distinct reason codes; no disable flag
  (`tests/test_authorize_binding.py`).
- **F-02 consume ledger**: durable SQLite
  `execution_authorization_consume` table; successful
  `verify_execution_authorization(..., consume_ledger=...)` claims the
  id atomically (`BEGIN IMMEDIATE` + UNIQUE). Caller
  `already_consumed` may only tighten. Restart-safe
  (`tests/test_consume_ledger.py`).

### Added
- **Multi-agent on the live decide path**: definitional dual-control +
  structural approval CABI attached by default (`PV_CROSS_AGENT=1`),
  escalation-only on HTTP `POST /v1/decide` and connector middleware when
  `execution_id` is declared; MCP forwards `_pv_execution_id`;
  `discover_loops` gates `POST /v1/authorize` when `security_events` are
  supplied (`tests/test_api_cross_agent.py`, `tests/test_dual_control.py`).
- **Self-hosted platform ops profile**: `GET /ready` store readiness,
  Prometheus decide-path metrics (`pv_decisions_total`, `pv_blocks_total`,
  `pv_decide_latency_seconds`, `pv_ready`), `GET /v1/ops/summary`,
  `docker-compose.platform.yml` (API + operator console + Prometheus),
  `tools/platform_demo.py`, `tools/init_platform_keys.py`, and
  `.well-known/security.txt`. Single-tenant self-hosted — does not claim
  SOC 2 / ISO / multi-tenant SaaS (`tests/test_platform_ops.py`).
- **PrivateVault Discovery Loop v1**: verified sealed history -> evidence-linked
  policy mining -> additive history and adversarial replay -> deterministic
  evaluation and structural probes -> ranked, human-reviewed PR proposals.
  Includes strict corpus/report schemas, full motivating record hashes,
  proposal notes, CLI, and an independent standard-library report verifier.
  It never applies policy; learned validation remains advisory and experimental
  Hodge/reachability probes remain quarantined (`agent_dna/discovery.py`,
  `spec/discovery-loop-v1/`, `docs/DISCOVERY-LOOP.md`,
  `tools/verify_discovery.py`, `tests/test_discovery.py`).
- **Agent Security Loop Discovery v1**: bounded deterministic analysis of
  cross-agent delegation, approval, invocation, dispatch, authorization reuse,
  causal ancestry, and repeated canonical actions. Strict JSON Schemas,
  deterministic witness paths and report digests, CLI exit-code contract,
  adversarial examples, an authority-boundary ADR, and malformed/replay/DoS
  regression coverage (`agent_dna/security/loop_discovery.py`,
  `spec/loop-discovery-v1/`, `docs/LOOP-DISCOVERY.md`,
  `tests/test_loop_discovery.py`).
- Operational trust invariant over real `InteractionEvent.trust` evidence,
  wired into the default cross-agent invariant engine. Material degradation is
  reviewable; severe degradation and malformed scores hard-block
  (`tests/test_trust_invariant.py`).
- Locked Python environment, strict typing gate for the security loop module,
  dashboard CI, CodeQL, Dependabot, release checklist, contribution policy, and
  repository-wide coding-agent security instructions.
- PrivateVault operator console replacing the generated Vite starter screen.
- **Authority Reachability v0.1-experimental**: deterministic blast-radius
  analysis over typed authority and company-knowledge graphs; explicit
  evidence classes; protected irreversible sinks; shortest-path witnesses;
  fail-closed conditions; direct-grant, issuer, and delegation-depth
  invariants; before/after change simulation; deterministic report hashes;
  signed report envelopes; JSON schemas; synthetic Agentforce vectors; and an
  offline runtime-coupled CLI
  (`experimental/authority_reachability_v01/`,
  `spec/authority-reachability-v01/`,
  `tools/pv_authority_reachability.py`; tests:
  `test_authority_reachability_v01.py`).
- **Authority Provenance v0.1-experimental**: strict trust-bundle, signed
  delegation-grant, and three-verdict receipt schemas; RFC 8785
  canonicalization over float-free I-JSON; Ed25519 key-usage enforcement;
  principal-and-key continuity; typed attenuation; independent authority and
  composition recomputation; runtime-coupled offline CLI; and two-axis authorisation
  readiness scan (`agent_dna/authority_v01.py`, `spec/authority-v01/`,
  `tools/pv_authority_cli.py`; tests: `test_authority_v01.py`,
  `test_authority_scanner_v01.py`).
- **pv-validation/1**: hash-sealed model-validation reports for the
  advisory drift layer — localized reliability by agent / capability /
  agent×capability with Wilson CIs, exact global-AUC within/between
  decomposition, calibration metrics (Brier, log loss, ECE) for
  declared probability scores only, label-shift vs concept-drift
  distinction with closed-form prior-odds correction, min-sample and
  class-count safeguards, independent-label requirement
  (`agent_dna/validation/`, `spec/validation/`,
  `docs/VALIDATION-MATH.md`; tests: `test_validation_*.py`).
- Stdlib-only validation verifier (`tools/verify_validation.py`),
  canonical vector with pinned hash (`test_validation_vectors.py`).
- `ValidationGuard`: optional runtime coupling via
  `PV_VALIDATION_REPORT` — tighten-only at the existing drift level,
  calibration warnings report-only, deterministic L0-L4 untouched
  (`test_validation_guard.py`).
- Real `LocalPolicyAdapter`: directory of YAML/JSON policies through
  the L2 `PolicyChecker`, deterministic order, fail-closed loading,
  evidence-honest skips (`test_local_policy_adapter.py`).
- Apache-2.0 `LICENSE`; threat-model `docs/SECURITY.md`;
  `CHANGELOG.md`.

### Changed
- Release metadata advanced to v0.4.0.
- Container runs as UID/GID 10001 and unauthenticated compose startup is no
  longer enabled by default.
- CI now gates Python formatting, linting, staged typing, the sealed proof run,
  spec vectors, dashboard lint/build, and a non-root container smoke test.
- README: status + 5-minute demo section; precedence list corrected
  to the 8-level contract (L2 customer policy was missing from the
  intro list; `spec/contracts/precedence-order.json` was already
  correct and CI-pinned).
- Packaging: `pyproject.toml` dependencies now exactly the imports of
  the core (removed unused sqlalchemy/alembic/cryptography); optional
  `[integrations]` extra for prometheus/kafka/redis/otel/pandas;
  `requirements.txt` mirrors core.
- `GitBundleAdapter` moved to `experimental/adapters/` with a
  deprecation shim — it was a non-firing stub presented as an adapter.
- docker-compose: healthcheck added so `--wait` gates on readiness.

### Fixed
- `/metrics` endpoint raised `NameError` on every call (undefined
  `body`/`content_type`); now serves Prometheus exposition with a
  stdlib fallback (`test_metrics_endpoint.py`).
