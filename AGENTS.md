# Repository instructions for coding agents

These rules apply to the entire repository.

Read `INVARIANTS.md` first. A change that breaks a promise there is wrong even
if every test passes; changing a promise needs an ADR and a maintainer's
sign-off.

1. Treat models as proposal-only components. They never receive credentials or
   mint authority.
2. Preserve fail-closed behavior at policy, authorization, dispatch, closure,
   persistence, security-loop, and offline-discovery boundaries.
3. Do not weaken strict schemas, canonical byte handling, signer independence,
   single-use authorization, or evidence verification to make a test pass.
4. Add an adversarial regression test for every security fix.
5. Keep product claims evidence-backed and update the limitations documents when
   behavior changes.
6. Run the Python, dashboard, and relevant Rust gates documented in
   `CONTRIBUTING.md` before handing off a change.
7. Discovery output is proposal-only: never auto-apply, auto-merge, or treat a
   priority score, synthetic label, advisory model, or model output as authority.
8. On the money path (decide, authorize, the sidecar, the receiver gate, the
   ledgers), run `uv run python -m demos.live_checkout.challenger --actions 20`
   and hand off only with no failing verdicts.
9. Say what you wrote: commits you helped write carry a `Co-authored-by:`
   trailer naming you, so a reviewer knows which lines to read most closely.
