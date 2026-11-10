# Multi-Agent Security Layer

Owner: Chandan Galani. Code: `agent_dna/multi_agent_security/`.
Tests: `tests/multi_agent_security/`. Demo:
`python examples/multi_agent_security_demo.py`.

A single-agent gate asks whether one agent's action is allowed. This layer
covers what goes wrong at the handoff between agents. It is deterministic:
signatures, hashes and operator-pinned configuration, no model.

## What it covers

| Failure at the handoff | Control | Module | On the live decision path? |
|---|---|---|---|
| **Authority laundering.** An agent that may not do something asks one that may. | Signed delegation chains in which each link can only narrow the one before it; verified offline. | `delegation.py` | No. Library, see below. |
| **Fake agreement.** Voters that share a model, provider or operator are one opinion counted several times. | `require_distinct` rule over what the operator declared about each voter. | `independence.py` | Yes, via `PV_CONSENSUS_FILE`. |
| **Replay.** A cleared quorum is presented again to another replica. | Single-use ledger in one SQLite file shared by every replica; one transaction per quorum. | `nonce_ledger.py` | Yes, via `PV_CONSENSUS_NONCE_DB`. |
| **Deniability.** Each party's log is its own word. | Each party keeps the other's signed checkpoints and audits later exports against them. | `counterparty.py` | No. Library and receipts. |

## Delegation (`pv-delegation/1`)

A chain is a list of links: `operator -> A -> B -> C`. Each link is signed by
its delegator's Ed25519 key, names the hash of the link before it, and may
only narrow it:

- every capability must be covered by the parent's (an exact name, or a
  prefix ending in a dot; there is no match-everything pattern);
- `max_amount` at most the parent's, unlimited only under unlimited;
- `expires_at` no later than the parent's;
- no onward link unless the parent set `may_delegate`.

The receiver calls `authorize(chain, anchors, agent_id=..., capability=...,
amount=...)` with operator-pinned `TrustAnchors` (root keys, agent keys,
revoked link hashes). It needs no service call. Refused, each by a named
test in `tests/multi_agent_security/test_delegation.py`: widened
capabilities, a raised or removed ceiling, a link that outlives its parent,
onward delegation without permission, an unpinned root, a link signed by
someone other than the holder, a forged signature, an edited link, links
spliced from two chains, a dropped middle link, cycles, expired or
future-dated links, a revoked link, and chains deeper than eight.

## Independence

```json
{
  "threshold": 2.0,
  "require_distinct": {"provider": 2, "operator": 2},
  "voters": [
    {"agent_id": "risk-1", "public_key": "...", "model": "m-large",
     "provider": "acme", "operator": "bank"},
    {"agent_id": "auditor", "public_key": "...", "model": "other-xl",
     "provider": "globex", "operator": "outside-firm"}
  ]
}
```

The approving voters must span at least that many distinct values. A voter
with no declared value contributes nothing, and a rule the roster could
never satisfy refuses startup. A quorum that reaches the threshold but not
the rule is held with `independence_shortfall`, and its votes are not spent.

## Single use across replicas

Set `PV_CONSENSUS_NONCE_DB` to a SQLite file every replica can open. A
quorum that clears is recorded in one transaction; a second presentation,
on any replica or after a restart, is held. `GET /v1/runtime` reports
`single-use: shared ledger` or `this process only`.

## Mutual checkpoints

`CounterpartyLedger(path, [their_public_key])` is one party's append-only
store of the other's checkpoints (`GET /v1/audit/checkpoint`):

- `accept(checkpoint)` keeps it if it is signed by the pinned key, intact,
  and does not go backwards from the last one held;
- `acknowledge(checkpoint, signer)` returns a signed `pv-checkpoint-ack/1`
  receipt the other party keeps as proof of disclosure;
- `audit(export_lines)` checks a later export against every checkpoint held.

## What this layer does not do

- **Delegation is not consulted by `/v1/decide`.** It is a library a
  receiving service calls before acting. Putting it on the precedence
  ladder is a change to the hash-pinned precedence contract and has not
  been made.
- **`max_amount` is per action.** Cumulative spend stays with the grant
  ledger.
- **Revocation lists are not distributed.** `TrustAnchors.revoked` is
  whatever the receiver was given; short expiries are the dependable
  control.
- **Independence is declared, not measured.** The rule runs over what the
  operator wrote in the roster. Nothing checks that a voter runs the model
  it is labelled with, or that two differently-labelled voters are
  independent in fact.
- **The shared ledger is one file.** Replicas on separate hosts with only
  PostgreSQL in common are not covered.
- **Checkpoint exchange is not automated.** There is no transport, schedule
  or dispute process; the ledger and receipts are the building blocks.
- **Prompt injection spreading from agent to agent is not addressed.**
- **Keys are identities.** Every guarantee here is about which pinned key
  signed, not about how the agent behind it behaves.
