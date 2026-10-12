# Persona 3: property broker

Listings, client follow-ups, viewings, and token payment requests at the
escrow partner. Amounts are INR. The only payee a token request may name is
the brokerage's escrow account, `ESCROW-BRK-001`.

```sh
uv run python agents/personas/property_broker/demo.py
```

## What it can do, needs approval for, and is blocked from

| Action | Outcome | Decided by |
|---|---|---|
| List properties | runs locally | read tool, no decision |
| Follow up a client, schedule a viewing | allowed, under a single-use clearance | grants `crm.follow_up`, `calendar.schedule_viewing` |
| Request a token up to 100,000 INR into escrow | allowed | grant `payments.request_token` (cumulative budget 2,000,000) |
| Request a token above 100,000 INR | needs the principal broker's approval | policy `token-above-threshold` |
| Request a token above 500,000 INR | blocked, an approval cannot lift it | policy `hard-cap` |
| Request a token into any payee other than escrow | blocked at decide | policy `payee-not-escrow` |
| Change the payee after approval | refused by the sidecar before any byte, and by the escrow gate if the sidecar is bypassed | permit bound to the exact bytes |
| Replay a permit | refused by the escrow gate | single-use ledger at the receiver |

## What the demo proves and what it does not

Proven in process: every token request is decided by PrivateVault from the
compiled rules; a diverted payee is blocked at decide and, if introduced
after approval, refused by the sidecar and by the escrow gate; approvals
are signed, single-use, and named by the permit; the escrow gate's receipt
chain verifies with its own key.

Not proven: a real CRM or escrow API (stub upstream), TLS peer identity
(demo transport), a real model (scripted), durable budgets.
