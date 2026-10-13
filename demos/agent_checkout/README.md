# Agent checkout demo

One procurement agent, one payment-gateway order API, one receiver gate
between them. About three minutes.

```sh
uv run python demos/agent_checkout/run.py            # paced for a meeting
uv run python demos/agent_checkout/run.py --fast     # no pauses
uv run python demos/agent_checkout/run.py --manual   # press Enter between steps
uv run python demos/agent_checkout/run.py --open     # also open report.html
```

Exit status 0 only if every check holds. Writes `report.html` next to
this file (self-contained, no scripts, no external resources) and keeps
the run's keys, ledgers, receipts and `timeline.json` in a temporary run
directory (`--run-dir` to choose one).

## The story

| Step | What happens | Where it is decided |
|---|---|---|
| 1 | The agent proposes an order: 18,500 INR to merchant M-1021 | nowhere yet; a proposal is bytes |
| 2 | Above 10,000 INR: `require_approval`. The procurement lead signs for exactly this action; the decision becomes ALLOW; a single-use permit is minted, bound to amount, payee and the exact order bytes | `/v1/decide`, approval bridge (ADR 0020), `/v1/authorize` |
| 3 | The sidecar sends the bytes; the receiver gate in front of the checkout API verifies the permit, consumes it, forwards once, signs a receipt. One order exists | receiver gate (ADR 0019) |
| 4 | Attack A: a note on the merchant page tells agents the price is now 85,000. The order is resubmitted with that amount under the same permit | sidecar refuses before any byte; gate refuses with `RECEIVER_WIRE_MISMATCH` when the sidecar is bypassed |
| 5 | Attack B: payee swapped to M-9999 | same two refusals |
| 6 | Attack C: the consumed permit replayed with the original bytes | gate refuses with `RECEIVER_PERMIT_CONSUMED` |
| 7 | A 2,50,000 INR cart, above the 2,00,000 hard cap, with a signed approval in hand | BLOCK at decide; the approval does not change it; nothing is minted |
| 8 | The gate's receipts are exported and verified with the gate's public key by a verifier that does not import PrivateVault | `tools/verify_receiver_receipts.py` |
| 9 | The same five requests against the bare API with a valid API key: all five become orders | the checkout API does its job; the gate is what was missing |

## What is real and what is mocked

Real: the PrivateVault API (decide, approval bridge, authorize), the
exact-byte sidecar, the receiver gate, its ledger, its receipts, and the
independent verifier. These are the shipped components, exercised the
same way the test suite exercises them.

Mocked, and said so in the code:

- The checkout API (`checkout_api.py`) has a real order shape
  (`order_id`, `amount`, `currency`, `merchant_id`, `callback_url`) and
  real shape validation, but it does not authenticate or dedupe. It stands
  in for an upstream that trusts whatever its caller is authorised to send.
- The model is scripted. The prompt injection is text in a fixture. A live
  model that follows it is refused the same way, because the refusal
  depends on the permit and the bytes, not on the model.
- The sidecar-to-gate transport is in process (`agents/core/transport.py`).
  The production transport derives peer identity from the TLS handshake.
- Keys are generated per run. A deployment pins the trust bundle and the
  approver bundle and keeps private keys with their owners.

## Files

| File | What |
|---|---|
| `run.py` | Terminal presenter: colour, pauses, the side-by-side table, exit status |
| `scenario.py` | The story as data: drives the harness, records every boundary into a timeline |
| `report.py` | Renders `report.html` from the timeline and the exported receipts |
| `checkout_api.py` | Mock payment-gateway order API |
| `tools.py` | The agent's tools; `create_checkout_order` is the money tool |
| `persona.yaml` | Identity, grant, policy (hard cap, approval threshold), approver |
| `INTEGRATION.md` | Three ways to put the gate in front of a real order API |

Tests: `tests/demos/test_agent_checkout.py`. The harness it reuses is
`agents/core/`; the receiver kit is `network/receiver_kit/`.
