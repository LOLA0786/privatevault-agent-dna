# External review — 2026-11-10

Independent review of `privatevault-agent-dna` at `main` (v0.4.0), performed
on a clean Ubuntu 24 container, Python 3.12.3. Everything below was executed,
not read: claims the reviewer could not run are listed as unverified, not
assumed.

## What was independently reproduced

| Claim | Command | Result |
|---|---|---|
| Test suite green | `pytest -q` (minus multi-instance, minus one root-incompatible test, see F-3) | **2516 passed, 69 skipped** |
| Adversarial corpus holds | `tools/run_adversarial.py` | **16 passed, 0 failed** |
| Fail-closed line, live log-tamper demo | `examples/composed_line_demo.py` | all levels exercised; tamper detected; circuit breaker survives restart |
| Lint gate | `ruff check` over CI's scope **plus `network/`** | clean after F-2 |
| Static typing | `mypy agent_dna api` | clean after F-1 (177 files) |
| Editable install from source | `pip install -e ".[dev]"` | clean |

## Not verified in this environment (environment-gated skips, by design)

- PostgreSQL store, grants, ledgers, shared state (`TEST_DATABASE_URL` unset).
- Multi-instance tests, Helm/kind install, receiver-kit Docker entrypoint
  (no Docker daemon).
- Rust signer parity (wheel not built).
- Live-model demos (`PV_LIVE_AGENT_TESTS`, `ANTHROPIC_API_KEY` unset).

These are exercised in the repository's own CI; nothing observed contradicts
that, but this review cannot vouch for them first-hand.

## Findings

Severity scale: blocker / high / low / informational. No blockers or highs
were found.

### F-1 (low, fixed): `key_custody.py` mypy ignore too narrow

`from google.cloud import kms  # type: ignore[import-not-found]` passes only
when the package is absent. On a machine where `google.cloud` is installed
without stubs (common: any transitively installed `google-*` package), mypy
fails with `import-untyped` *and* flags the ignore as not covering the error,
breaking the typing gate for contributors. Fixed by widening to
`[import-not-found,import-untyped,unused-ignore]`.

### F-2 (low, fixed): deliberate validation access trips B018 outside CI's lint scope

`network/receiver_kit/config.py` touches `settings.trust_bundle` for its
fail-at-startup side effect. CI's ruff invocation does not include `network/`,
so the useless-expression violation is invisible to the gate but fires for
anyone running `ruff check .`. Fixed with an explicit `_ =` assignment; the
intent comment is preserved. Recommend also adding `network` to the CI lint
and format scope so the gap cannot reopen.

### F-3 (low, fixed): permission test fails under root

`tests/network/test_receiver_kit.py::test_unreadable_key_file_error_is_actionable`
chmods a key to 0000 and expects a `ConfigError`. Root (the default user in
most containers, including this review's) bypasses file modes, so the test
fails spuriously and `-x` runs halt. Fixed with a
`skipif(os.geteuid() == 0)` guard carrying an explanatory reason.

### F-4 (informational, open): unauthenticated `/metrics`

Already tracked as open in `docs/findings/PHASE1-FOLLOW-UPS.md`. Mitigations
(network policy, scrape-side auth) belong in the deployment docs until closed;
the Helm chart should state the assumption explicitly.

### F-5 (informational): generated HTML at repository root

`architecture.html`, `scenarios.html`, `meeting-dashboard.html`,
`test-index.html` (≈0.5 MB combined) are generated artifacts
(`tools/gen_*.py`, mapped in `docs/architecture/REPO-MAP.md`). Legitimate, but
a first-time reader cannot tell them from source. Consider moving them under
`site/` or publishing via GitHub Pages from CI instead of committing them.

## Readiness assessment

The repository does the things that distinguish a product from a demo:

- **Enforcement is deterministic and fail-closed**, and the properties are
  pinned by named tests rather than asserted in prose. The precedence order
  is a hash-pinned contract with a CI drift check.
- **Verification does not require trusting the repo**: chain and signature
  verifiers are stdlib-only, and the wire format lives in a separately
  published spec.
- **Honesty artifacts exist and are current**: `WHAT-WE-DO-NOT-CLAIM.md`,
  a threat model, a fixed-issues log in `SECURITY.md` naming the pinning
  test for each fix, and an open-findings ledger.
- **Operational story is real**: PostgreSQL-backed shared state, Helm chart
  verified on kind in CI, signed backup/restore, scoped API keys hashed at
  rest, production startup refusing to run without keys.

Verdict: **ready for pilot deployments within the scope the documentation
claims**, with F-4 communicated to operators and the environment-gated test
tiers re-run in the operator's own infrastructure before promotion.

## Changes made in this review

- `agent_dna/key_custody.py` — F-1.
- `network/receiver_kit/config.py` — F-2.
- `tests/network/test_receiver_kit.py` — F-3.
- `README.md` — CI, CodeQL, license, and Python badges.
- This document.

All touched paths re-verified: ruff clean (including `network/`), ruff format
clean, `mypy agent_dna api` clean, targeted tests 46 passed / 3 skipped with
reasons.
