# 0012 — Python and Rust maintain CI parity

Status:     accepted
Date:       2026-07-19
Commit:     061436fb6c3460139617ccc1e80878f36eb7286e
Pinned by:  rust/tests/canonical_parity.rs::float_repr_matches_cpython

## What forced the decision
A second implementation is how you stop trusting the first. It is
also how you fork the hash chain: serde_json will emit `1e17`
where CPython emits `1e+17`, Unicode and `-0.0` diverge, and two
verifiers that both "work" will disagree on `record_hash`. The
tempting alternative is "Rust is faster, close enough," or to
"fix" a failing vector by regenerating it from Rust.

Python CI does not install the wheel, so a parity test that only
lives in pytest would skip on the main gate and rot. That is why
parity is a separate workflow that builds the wheel and then
refuses to ship if the chains fork.

## The decision
Canonical JSON, float repr, Ed25519 signatures, and spec-vector
`record_hash` values must be byte-identical across Python and
Rust. On disagreement, fix Rust (or the Python sealer), never the
committed vector. `.github/workflows/rust.yml` runs `cargo test`,
`tools/rust_parity_check.py`, `tests/test_rust_conformance.py`,
and signer parity after `maturin build`. Pytest modules that
`importorskip("pv_runtime")` are not the gate; they are the
laptop-friendly shadow of it.

## What this costs us
CPython JSON quirks are now a load-bearing protocol. Changing
Python's sealer is a two-language migration. The Python CI job
can be green while Rust is red, and the reverse is a full Python
suite inside the Rust job. Toolchain pins (1.97.1) are part of
the contract.

## What would make us revisit
A third independent verifier in a language neither of these
implementations control, consuming only drp-spec. Dropping Rust
to cut CI minutes, or regenerating spec vectors from Rust to
make a test pass, is not a trigger.
