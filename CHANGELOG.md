# Changelog

Claims discipline applies here too: every entry corresponds to code
and a named test that runs in CI.

## Unreleased

### Added
- **Authority Provenance v0.1-experimental**: strict trust-bundle, signed
  delegation-grant, and three-verdict receipt schemas; RFC 8785
  canonicalization over float-free I-JSON; Ed25519 key-usage enforcement;
  principal-and-key continuity; typed attenuation; independent authority and
  composition recomputation; offline verifier; and two-axis authorisation
  readiness scan (`agent_dna/authority_v01.py`, `spec/authority-v01/`,
  `tools/verify_authority_v01.py`; tests: `test_authority_v01.py`,
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
