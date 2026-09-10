# PrivateVault Connector Engineering Standard

Rules for any code on or near the enforcement path. Each rule states
how a violation is caught — a rule nobody can catch you breaking is
a slogan, not a standard.

## 1. No mocks on the enforcement path
Integration tests for enforcement run a real harness client, real
adapter, real middleware, real engine, real breaker, real key
registry, real recorder. Stubs are permitted in exactly two places:
the drift scorer (synthetic until a real pilot provides real traces
— see WHAT-WE-DO-NOT-CLAIM.md) and the tool being guarded.
*Caught by:* CI guard test — `tests/connector/` must not import
`unittest.mock` or `pytest-mock`.

## 2. Every runtime guarantee has at least one integration test
If a sentence appears in a deck, README, or outreach message
("suspension survives restart", "audit keys cannot enforce",
"refusals are signed in-band"), a test exercises it end-to-end.
No test, no claim.
*Caught by:* claims review against the test suite before any
external document ships.

## 3. Fail-closed at every layer, including new ones
Missing identity, connector fault, engine fault, verifier fault —
each maps to BLOCK, never to a default verdict, never to "warn".
A component that defaults open on error is rejected at review
regardless of what else it does.
*Caught by:* every new enforcement component ships with an
explicit fault-injection test (sabotaged dependency -> BLOCK).

## 4. Verify before wiring
No code is written against a guessed interface. Inspect the actual
signature, schema, or SDK surface first — including third-party
SDKs, where the installed version is inspected directly rather
than trusting documentation or memory.
*Caught by:* interface mismatches at test time; repeated guesses
in one work session are a process failure, not bad luck.

## 5. Green gates commits
Test-run and commit are one gated chain (`pytest && git commit`).
A commit that lands red on master is treated as an incident:
fixed forward immediately, cause noted.
*Caught by:* CI on master; the push log.

## 6. Anchored patches only
Modifications to existing files assert their anchor text exists
before writing (and assert non-duplication where applicable).
Silent sed against drifted files is prohibited on enforcement code.
*Caught by:* the patcher itself failing loudly.

## 7. Private-surface dependencies are declared
Any binding to a third-party private API (e.g. MCPServer
`_tool_manager`) is listed in
PRODUCTION-HARDENING.md with its version pin and the integration
test that fails loudly if the surface changes.
*Caught by:* the listed test breaking on SDK bumps.

## 8. Found bugs become pinned tests
A bug discovered in development (race, scope bypass, timing
side-channel) is fixed together with a test that reproduces the
original failure — in the same commit. The bug's story goes in the
audit narrative; discovering our own bugs first is evidence the
process works, not something to hide.
*Caught by:* commit review — a fix without its reproduction test
is incomplete.
