# Persona 2: interior design firm

Client quotes and vendor purchase orders. The agent reads a project brief,
sends the client a quote, issues purchase orders to approved vendors through
the procurement network, and keeps the client informed. Amounts are INR.

```sh
uv run python agents/personas/interior_design/demo.py
```

## What it can do, needs approval for, and is blocked from

| Action | Outcome | Decided by |
|---|---|---|
| Read a project brief | runs locally | read tool, no decision |
| Send a client quote | allowed, under a single-use clearance | grant `quotes.send` |
| Issue a PO up to 50,000 INR to an approved vendor | allowed | grant `procurement.issue_po` (cumulative budget 1,000,000) |
| Issue a PO above 50,000 INR | needs the studio owner's approval | policy `po-above-limit` |
| Issue a PO above 200,000 INR | blocked, an approval cannot lift it | policy `hard-cap` |
| Issue a PO to a vendor not on the approved list | blocked | policy `unapproved-vendor` |
| Notify the client | allowed, under a clearance | grant `comms.notify_client` |
| Swap the vendor or amount after approval | refused by the sidecar before any byte, and by the vendor network's gate if the sidecar is bypassed | permit bound to the exact bytes |

## What the demo proves and what it does not

Proven in process: every PO is decided by PrivateVault from the compiled
rules; the owner's approval is a signed, single-use artifact the permit
names; the sidecar refuses a swapped vendor before sending; the vendor
network's gate refuses it when the sidecar is bypassed; the gate's receipt
chain verifies with its own key.

Not proven: a real project system or procurement API (stub upstream), TLS
peer identity (demo transport), a real model (scripted), durable budgets.
