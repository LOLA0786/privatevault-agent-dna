# Contributing

PrivateVault is security-boundary software. A change is complete only when its
failure behavior, evidence semantics, and operator-facing claim are tested.

## Development setup

```bash
uv sync --locked --extra dev
uv run pytest -q
```

Before opening a pull request, run the same local gates as CI:

```bash
uv run ruff format --check agent_dna api tests tools examples experimental benchmarks
uv run ruff check agent_dna api tests tools examples experimental benchmarks
uv run mypy agent_dna api
uv run mypy --strict --follow-imports=skip agent_dna/security
uv run python tools/prove.py -o /tmp/proof-of-run.json
npm --prefix dashboard ci
npm --prefix dashboard run lint
npm --prefix dashboard run build
```

Rust changes additionally require `cargo fmt --check`, `cargo clippy
--all-targets -- -D warnings`, and `cargo test` from `rust/`.

## Security invariants

- Model output is a proposal, never authorization evidence.
- Missing, malformed, unverifiable, expired, or reused authority fails closed.
- Dispatch operates on the exact bytes covered by authorization and witness
  evidence.
- `BLOCK` and `REVIEW` are not dispatchable outcomes.
- Do not retry an indeterminate dispatch unless independent evidence proves the
  first attempt did not execute.
- Every new claim must name a test, schema, or independently verifiable artifact.

Keep pull requests focused, update `CHANGELOG.md`, and add regression coverage
for every security-relevant bug.
