# 0013 — Open-core split: drp-spec Apache-2.0, runtime commercial

Status:     accepted
Date:       2026-07-08
Commit:     532dcc3a440d883363d96e6d4ae6e8a9d0310516
Pinned by:  no pinning test for the commercial license. tests/test_verifier_independence.py::test_independent_verifiers_have_no_repository_imports pins only that the public verifier does not import this runtime.

## What forced the decision
If the audit format is proprietary, a customer who leaves still
cannot prove their own history, and every RFP dies on vendor lock-in.
If the enforcement runtime is given away under the same terms as
the spec, there is no product — only a library competitors will
wrap. Dual-licensing the spec as "open except you cannot verify
without us" is the version of open-core that procurement has
learned to reject.

The tempting alternative in this tree is to treat `LICENSE` as
the whole story. This repository currently ships Apache-2.0 in
`LICENSE` and `pyproject.toml`. That undercuts a commercial runtime
claim unless the paid surface lives elsewhere or the license is
later narrowed. We still made the split as a product decision:
customers must verify without us; we sell the monitor.

## The decision
The DRP wire format, schemas, test vectors, and stdlib verifier
are published independently (Apache-2.0 / CC-BY-4.0 in drp-spec)
so an auditor does not import `agent_dna`. The decision runtime —
precedence, mint, sidecar, gateway — is the commercial product.
Runtime-coupled CLIs (authority, reachability) must say so rather
than pose as independent verifiers. `rust/deny.toml` treats
`pv_runtime` as unpublished/commercial for dependency policy even
while this Python tree remains Apache-2.0 licensed.

## What this costs us
Anyone can run this Apache-2.0 tree today; the commercial frame
in `docs/PILOT-SCOPE.md` is not enforced by a test or by this
repo's `LICENSE`. We owe a relicensing or a clearly separate
product repo before the sales sentence and the tarball match.
Keeping the verifier independent costs us a second implementation
that must stay in lockstep with the spec.

## What would make us revisit
A paid distribution with a non-Apache license and a test that the
published verifier still has no runtime imports. Relicensing
drp-spec to close verification would reverse the split. Quietly
editing PILOT-SCOPE to say "everything is Apache" without changing
the verifier boundary is not a decision; it is a docs drift.
