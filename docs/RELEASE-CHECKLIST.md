# Release checklist

## Integrity

- [ ] Version matches `pyproject.toml`, FastAPI metadata, API docs, and changelog.
- [ ] `uv.lock` is current and CI uses the locked environment.
- [ ] Python lint, format, typing, tests, proof generation, and spec vectors pass.
- [ ] Dashboard lockfile, lint, and production build pass.
- [ ] Rust formatting, clippy, tests, parity vectors, audit, and deny checks pass.

## Security

- [ ] New authority paths have malformed, unavailable, replay, and reuse tests.
- [ ] `REVIEW`, `BLOCK`, and indeterminate execution paths cannot dispatch.
- [ ] Exact-byte witness and closure evidence remain independently verifiable.
- [ ] Loop discovery is run for consequential multi-agent traces and its report
      digest is retained with execution evidence.
- [ ] Offline Discovery Loop reports pass `tools/verify_discovery.py`; every
      emitted proposal has a named human owner and no auto-apply path.
- [ ] No secret, local database, cache, dependency tree, or generated build output
      is present in the release archive.

## Claims and operations

- [ ] `CHANGELOG.md`, API docs, threat model, and non-claims match shipped code.
- [ ] Container starts as a non-root user and refuses unauthenticated startup by
      default.
- [ ] Upgrade, rollback, backup, and key-rotation steps are reviewed for the target
      deployment.
- [ ] Release tag, source archive checksum, and proof-of-run artifact are recorded.
