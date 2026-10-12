# Persona 1: finance operations

Invoice to payment instruction. The agent reads an invoice, checks for a
matching purchase order, creates a payment instruction at the payments
receiver, and tells the AP team. Amounts are INR.

Run the demo from the repository root:

```sh
uv run python agents/personas/finance_ops/demo.py
```

## What it can do, needs approval for, and is blocked from

| Action | Outcome | Decided by |
|---|---|---|
| Read an invoice, match a purchase order | runs locally | read tools, no decision |
| Pay up to 5,000 INR to a known vendor with a matching PO | allowed | grant `payments.pay_invoice` (cumulative budget 100,000) |
| Pay more than 5,000 INR | needs approval | policy `above-approval-threshold` |
| Pay without a matching PO | needs approval | policy `no-matching-po` |
| Pay more than 50,000 INR | blocked, an approval cannot lift it | policy `hard-cap` |
| Pay a payee outside the vendor master | blocked | policy `unknown-payee` |
| Notify the AP team | allowed, under a single-use clearance | grant `comms.notify_ap` |
| Change the amount or payee after approval | refused by the sidecar before any byte, and by the receiver if the sidecar is bypassed | permit bound to the exact bytes (ADR 0017, 0019) |
| Replay a permit | refused by the receiver | single-use ledger at the receiver (ADR 0019) |

The approver is the CFO. An approval is a signed `approval_v01` artifact for
the exact action digest; it is single-use, must come from someone other than
the agent, and the permit names it (ADR 0020).

## What the demo proves and what it does not

Proven in process, every run: the decision for every payment is made by
PrivateVault from the compiled policy and grants; approvals are verified
and consumed; the permit is minted once per decision and bound to the exact
bytes; the sidecar refuses altered bytes before sending; the receiver gate
refuses altered bytes and replays even when the sidecar is bypassed; the
receiver's receipt chain verifies with its own key in an isolated
interpreter.

Not proven here: a real AP system or payments API (the upstream is the
receiver kit's stub); TLS peer identity (the demo transport uses a fixed
label, the production transport derives it from the handshake); a real
model (the demo and tests use a scripted model; `PV_AGENT_MODEL=anthropic`
is opt-in); durable budgets (the grant budget is cumulative in process and
resets on restart, as the product's non-claims state).
