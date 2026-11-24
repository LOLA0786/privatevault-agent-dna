# Contributing

PrivateVault is security-boundary software. A change is complete only when its
failure behavior, evidence semantics, and operator-facing claim are tested.
New to the project? Start with [docs/ONBOARDING.md](docs/ONBOARDING.md).

## Development setup

Use the repository toolchain only. Do not put other checkouts on a global
`PYTHONPATH`; that can shadow this repo's `tests` package and break
collection.

```bash
uv sync --locked --extra dev
uv run pytest -q
```

`uv sync` respects `.python-version` (CPython 3.12). Set `TEST_DATABASE_URL`
to a PostgreSQL 16 server to include the PostgreSQL tests, as CI does.

## Gates

Run the same gates as CI before opening a pull request.
`tests/test_contributing_gates.py` fails if this list and
`.github/workflows/ci.yml` disagree. A line starting with `!` must fail.

```bash
uv run ruff format --check agent_dna api tests tools examples experimental benchmarks agents proof demos integrations end_to_end_coding_agents_demo.py opa_decision_demo.py
uv run ruff check agent_dna api tests tools examples experimental benchmarks agents proof demos integrations end_to_end_coding_agents_demo.py opa_decision_demo.py
uv run mypy agent_dna api
uv run mypy agents proof demos
uv run mypy --strict --follow-imports=skip agent_dna/security
uv run python end_to_end_coding_agents_demo.py
uv run python tools/prove.py -o /tmp/proof-of-run.json
uv run python tools/verify_records.py spec/test-vectors/clean.jsonl
! uv run python tools/verify_records.py spec/test-vectors/tampered_field.jsonl
! uv run python tools/verify_records.py spec/test-vectors/deleted_record.jsonl
! uv run python tools/verify_records.py spec/test-vectors/divergent.jsonl
uv run python tools/generate_test_vectors.py --out /tmp/ci_vecs
uv run python tools/verify_records.py /tmp/ci_vecs/clean.jsonl
```

Dashboard changes: in `dashboard/`, `npm ci`, `npm run test:deps`,
`npm run audit:check`, `npm run lint` and `npm run build`. Changes to
`privatevault-gate/`: `npm ci` and `npm test` there. Rust changes:
`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` and
`cargo test` from `rust/`.

## Invariants

The promises in [INVARIANTS.md](INVARIANTS.md) are hard lines: a change that
breaks one is wrong even if every other test passes, and changing a promise
takes an ADR. Beyond them, two rules of practice:

- `BLOCK` and `REVIEW` are not dispatchable outcomes.
- Do not retry an indeterminate dispatch unless independent evidence proves
  the first attempt did not execute.

## Working with AI assistants

We build PrivateVault with AI assistants, and say so. These rules keep a
person accountable for every line.

- A named person owns each change. An assistant may draft code, tests and
  documentation; the owner reads every changed line in the trusted core
  (listed in [docs/ONBOARDING.md](docs/ONBOARDING.md)) before it merges.
- Disclose it. A commit an assistant helped write carries a `Co-authored-by:`
  trailer naming the assistant, never a placeholder identity.
- Generated output is not evidence. A test proves a claim only if a person has
  read it and seen it fail without the change; show that failing run in the
  pull request.
- Keep pull requests small. Generated code that nobody on the team can explain
  is deleted, not merged.
- Coding agents work from [AGENTS.md](AGENTS.md) and
  [INVARIANTS.md](INVARIANTS.md). Briefs that shaped the design are kept in
  [docs/process/](docs/process/architecture-map-brief.md).

## Pull requests

Keep pull requests focused, update `CHANGELOG.md`, and add an adversarial
regression test for every security fix.
