# Evaluate PrivateVault in one day

This guide is for an engineer or security reviewer at a bank, fintech, or
agent platform who has a day and wants to decide whether the claim holds:
an agent with valid credentials cannot move money it was not approved to
move, and the proof is checkable without trusting us.

## Prerequisites

- Docker with Compose v2, or Python 3.12 with `uv`.
- This repository cloned. No API keys, no accounts, no network beyond
  pulling the base image.

## Morning: run the proofs and read them

```sh
docker compose -f proof/docker-compose.yml up --build --abort-on-container-exit
```

or `uv run python -m proof.run_all`. It prints three blocks and exits 0
only if all three hold.

- **P1 comparison.** One attack (valid credentials, amount or payee
  changed after approval) against an LLM guardrail stub, an API gateway
  with an amount cap, strict idempotency keys, and the PrivateVault
  receiver gate. Read `proof/compare/RESULTS.md` and the assumptions in
  `proof/compare/README.md`. The question to settle for yourself: is any
  of the first three modelled unfairly? Each is the strict version of the
  mechanism it claims to be, and each admits the honest request.
- **P2 before/after.** The same finance-ops flow with PrivateVault off (the
  upstream receives 48,000) and on (refused by the sidecar and by the
  receiver; the upstream receives only the approved 18,000).
- **P3 injection.** An invoice note tells the model to pay another account.
  Without PrivateVault the attacker is paid; with it the payee is blocked at
  decide, and a payee injected after approval is refused twice.

Then run the pinning tests behind the attack table in
`docs/THREAT-MODEL.md`:

```sh
uv run pytest -q tests/proof tests/agents tests/receiver tests/test_approval_bridge.py
```

## Midday: run a receiver on your own machine, with your own key

Follow `network/receiver_kit/QUICKSTART.md` (about 15 minutes). You
generate the receipt key; the gate runs as a reverse proxy in front of a
stub upstream; `send_test.py` sends a valid permit, the same permit with
the amount changed, and a replay. Then export the receipts and verify them
with `tools/verify_receiver_receipts.py`, which does not import this
package. What you have at the end is a receipt chain signed by a key only
you hold, saying the gate admitted one action and refused two.

## Afternoon: change the rules, then try to break it

1. Open `agents/personas/finance_ops/persona.yaml` and lower the approval
   threshold from 5,000 to 2,000. Run
   `uv run python agents/personas/finance_ops/demo.py`. Invoice INV-1001
   (4,200 INR) now needs the CFO's approval before it executes; the demo
   checks will say so.
2. Add a vendor to the vendor master list and watch INV-1003 stop being
   blocked at decide. Remove it again.
3. Try to defeat the binding from inside the agent process:
   `agents/core/gate.py` is small. Change the bytes between `mint` and
   `dispatch` (`tests/agents/test_finance_ops.py::test_amount_change_after_approval_is_refused_twice`);
   mint twice for one decision
   (`tests/test_authorize_mint_claim.py::test_sequential_mint_returns_byte_identical_authorization`);
   present a permit to the receiver with a different body
   (`tests/receiver/test_receiver_gate.py::test_amount_swap_refused`);
   replay a permit
   (`tests/receiver/test_receiver_gate.py::test_replay_refused_by_receiver_ledger`);
   sign an approval with a key that is not in the approver bundle
   (`tests/test_approval_bridge.py::test_unpinned_approver_is_refused`);
   approve your own action
   (`tests/test_approval_bridge.py::test_approver_must_differ_from_requester`).
   Every one of these has a test in `docs/THREAT-MODEL.md` that says what
   should happen. If you find one that does not, that is the finding we
   want.

## Success criteria

Tick each one with the output in front of you.

- [ ] `proof/run_all.py` printed `ALL PROOFS HOLD` and exited 0.
- [ ] P1: the receiver gate row shows `refused (RECEIVER_WIRE_MISMATCH)`
      for both alterations and `admitted` for the honest request; the
      other three rows show `admitted` throughout.
- [ ] P2: before, upstream amounts `['48,000']` and `decision records: 0`;
      after, `RECEIVER_WIRE_MISMATCH` and upstream amounts `['18,000']`.
- [ ] P3: `paid 18,000 INR to ACCT-ATTACKER` without PrivateVault;
      `decision=block policy=unknown-payee` with it; the late injection
      refused by sidecar and receiver.
- [ ] The receiver kit verifier printed `OK ... mode=chain+signatures`
      with the public key you generated.
- [ ] After lowering the threshold, INV-1001 required approval.
- [ ] `uv run pytest -q tests/proof tests/agents tests/receiver` passed.

## Architecture

```mermaid
flowchart LR
  subgraph agent["Agent process (holds API credentials)"]
    M["Model: proposes tool calls only"] --> R["Runner"]
    R --> S["Exact-byte sidecar: verify, consume, send once"]
  end
  subgraph pv["PrivateVault"]
    D["/v1/decide: policy, grants, drift"]
    B["Approval bridge: verified, single-use (ADR 0020)"]
    A["/v1/authorize: one permit per decision, bound to exact bytes"]
    D --- B --- A
    L[("Decision records, mint and approval ledgers")]
  end
  H["Human approver: signed approval for the exact action"] --> R
  R -->|decide| D
  R -->|authorize| A
  S -->|permit header plus exact bytes| G
  subgraph recv["Receiver (system of record), operated by its owner"]
    G["Receiver gate: verify, consume, sign receipt (ADR 0019)"] --> U["Upstream API"]
    G --- RL[("Receiver ledger and receipt chain")]
  end
  V["Independent verifier (no PrivateVault code)"] -.-> RL
```

Trust boundaries: the model never holds credentials; the agent process
holds credentials but cannot mint; PrivateVault mints but cannot execute;
the receiver executes only what verifies against bytes it received; the
verifier checks the receiver's receipts with a key the receiver published.

## What this evaluation does not establish

See `docs/THREAT-MODEL.md`, "Non-goals", and `docs/WHAT-WE-DO-NOT-CLAIM.md`.
In short: complete mediation of raw sockets, a compromised receiver
operator, model quality, durable budgets, multi-host single-use, and TLS
peer identity in the demos.
