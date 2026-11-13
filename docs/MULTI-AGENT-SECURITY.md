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
| **Authority laundering / copied chains.** An agent widens delegated rights or claims another agent's identity. | Narrowing signed chains plus a single-use, request-bound proof of the final delegate's pinned key. | `delegation.py`, `possession.py`, `gate.py` | Yes, via `PV_DELEGATION_FILE`. Also a library. |
| **Fake agreement.** Voters that share a model, provider or operator are one opinion counted several times. | `require_distinct` rule over what the operator declared about each voter. | `independence.py` | Yes, via `PV_CONSENSUS_FILE`. |
| **Replay.** A cleared quorum or a delegation presentation is used again on another replica. | Single-use ledger shared by every replica: PostgreSQL, or one SQLite file; one transaction per use. | `nonce_ledger.py` | Yes. PostgreSQL automatically with `PV_DATABASE_URL`, else `PV_CONSENSUS_NONCE_DB`. |
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

The receiver uses operator-pinned `TrustAnchors` (root keys, agent keys,
revoked link hashes), including a pinned key for the **final delegate**.
`verify_chain` checks authority only; it does not authenticate a caller.
Refused, each by a named
test in `tests/multi_agent_security/test_delegation.py`: widened
capabilities, a raised or removed ceiling, a link that outlives its parent,
onward delegation without permission, an unpinned root, a link signed by
someone other than the holder, a forged signature, an edited link, links
spliced from two chains, a dropped middle link, cycles, expired or
future-dated links, a revoked link, and chains deeper than eight.

## Delegation on `/v1/decide`

Set `PV_DELEGATION_FILE` and the runtime checks delegation on every decision
(`gate.py`). The operator pins:

```json
{
  "audience": "pv-prod-eu",
  "roots":  {"operator": "<ed25519 public key>"},
  "agents": {"planner": "<key>", "payer": "<key>"},
  "revoked": ["<link hash>"],
  "revoked_agents": ["retired-agent"],
  "required_for": ["payments."],
  "required_agents": ["payer"]
}
```

The caller sends `evidence.delegation = {"chain": [...], "presentation": {...}}`.

- **It only restricts.** The agent's own grant is still checked; the action
  must be inside both. A valid chain grants nothing.
- **A chain is mandatory where the operator says so.** An agent in
  `required_agents`, or any agent using a capability in `required_for`, is
  held without one, so a sub-agent cannot fall back on a standing grant.
- **The holder must prove its key, for the action as it will run.** The
  presentation is signed by the final delegate's pinned key over this
  chain, this deployment's `audience`, a lifetime of at most 120 seconds,
  and one exact action: the agent, capability and arguments, and the
  dispatch the runtime seals for the request (destination, operation,
  transport, adapter, serialization, content type, resource, and the
  principal acted as). Change
  any of them and the presentation is refused; build the value to sign
  with `delegated_action_id(agent, capability, arguments,
  sealed_dispatch(execution_action, dispatch_context))`. It is spent once
  in the shared ledger. A copied chain without the key is refused.
- **A refusal is a BLOCK (403), not a hold.** A missing, forged,
  out-of-scope or replayed delegation is not a question for a person. As a
  hold, an interactive client such as the Claude Code hook would show it as
  a prompt its user could answer "allow".
- **An allowed decision made under a presented chain carries it to the
  mint**, whether the engine allowed it outright, a person approved a hold,
  or a quorum cleared it. A decision made with no chain carries no seal;
  the last bullet of this list is what covers that case. The sealed reason
  ends with the chain hash, every link hash, every identity in the chain
  with the key it verified under, and when the delegated authority ends.
  `/v1/authorize` reads it back and refuses to mint when:
  - that time has passed (and it caps a permit's expiry at it);
  - an identity or link in the chain is revoked;
  - an identity in the chain is no longer pinned, or is pinned under a
    different key (a rotation or removal withdraws what was decided);
  - the configuration requires a chain for the agent or capability and the
    record carries no seal.

  The expiry is in the signed record, so any replica applies it. The
  revocation checks use the configuration of the server doing the mint:
  see the limits below. Tests: `tests/multi_agent_security/test_mint.py`.
- **A revoked identity gets nothing.** An agent in `revoked_agents` is
  refused on every decision, with or without a chain, and does not mint.
- **The configuration file is followed.** A change to `PV_DELEGATION_FILE`
  is picked up on the next decision or mint with no restart. If the changed
  file does not load, every decision the gate is asked about is refused and
  nothing mints, sealed or not, until it loads. Decisions and mints that
  never reach this server's gate are outside that statement.
- **A chain is required by capability name, folded.** `required_for`
  matches after folding case, compatibility forms and whitespace, and a
  capability that is not plain ASCII always needs a chain while
  `required_for` is in use, so `CRM.read_contact` does not walk past
  `crm.`. What a chain grants is still compared exactly. This guards
  names only: nothing here ties a capability name to what is actually
  sent. `PV_OPERATIONS_FILE` does that, and `required_agents` does not
  depend on names at all.
- **Names must be exact.** Identity names, and every name in
  `revoked_agents` and `required_agents`, must match a pinned identity
  character for character; a name with stray whitespace, different
  capitalization or no match refuses to load. A repeated key in the file
  refuses to load. Consensus voter names follow the same whitespace rule.

`sign_presentation(...)` belongs in the agent's credential broker, never in
the model. `GET /v1/runtime` reports the gate under `composition.delegation`.
An invalid file refuses startup. Tests: `tests/multi_agent_security/test_gate.py`.

The library path (`authorize` with `DelegationChallenges`, below) uses a
receiver-issued challenge held in one process's memory. `/v1/decide` is a
single call that may land on any replica, so the gate uses a self-contained
signed presentation whose single use is recorded in the shared ledger.

### Caller possession for library use (`pv-delegation-proof/1`)

**Breaking security change:** calling `authorize` with only a chain and an
`agent_id` now refuses with `delegation_proof_required`. There is no bearer
fallback. The final delegate must sign a receiver-issued challenge.

```python
from hashlib import sha256
from agent_dna.multi_agent_security import (
    DelegationChallenges, authorize, link_hash, sign_possession,
)

# Receiver startup: keep this instance, do not rebuild it from agent input.
challenges = DelegationChallenges("payments-service")

# Receiver freezes the complete request bytes and derives these claims from
# them. Include destination, method, path, headers and body as appropriate.
request_hash = sha256(request_bytes).hexdigest()
challenge = challenges.issue(
    chain_hash=link_hash(chain[-1]), agent_id="payer",
    capability="payments.pay_invoice", amount=80, request_hash=request_hash,
)

# Send the challenge over authenticated transport. The delegate's trusted
# broker checks its contents and signs; never expose the key to a model.
proof = sign_possession(payer_signing_key, challenge)

# Receiver still holds the exact request bytes and its own challenge state.
decision = authorize(
    chain, anchors, agent_id="payer", capability="payments.pay_invoice", amount=80,
    proof=proof, challenges=challenges, request_hash=request_hash,
)
```

The proof binds the audience, nonce, expiry, chain hash, agent, capability,
amount and request hash. Challenges expire within 60 seconds; a monotonic
deadline prevents a wall-clock rollback extending that window. Consumption
is atomic across threads of the same receiver instance. A proof cannot
authorize a changed request or be reused. A copied chain without the final
delegate's private key cannot produce a proof. The challenge store bounds
pending requests and refuses when full.

**Deployment boundary:** transport and execution are not implemented here.
The receiver must compute the digest from the exact bytes it will dispatch,
derive the capability and amount from that same request, and require ALLOW
before dispatch. An unchecked caller-supplied digest does not provide that
binding. Pending challenges are in memory; another instance or restart
refuses them. Route the response to the issuing instance. This is not a
durable payment idempotency ledger: a new challenge can authorize a new
attempt, so an indeterminate payment still requires independent reconciliation.

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

A quorum that clears, and a delegation presentation that verifies, is
recorded in one transaction; a second use, on any replica or after a
restart, is held. Where the record lives:

| Setting | Ledger | Covers |
|---|---|---|
| `PV_DATABASE_URL` set | PostgreSQL table `used_votes` | replicas on separate hosts |
| `PV_CONSENSUS_NONCE_DB=<file>` | SQLite file | replicas sharing a host or volume |
| neither | process memory | one process |

`GET /v1/runtime` reports `single-use: shared ledger` or `this process only`.

A used entry is kept for 300 seconds after it expires, so a replica whose
clock runs ahead cannot free a vote that a slower replica would still
accept. A ledger that cannot be written refuses startup, including the case
where only the database file is read-only: the startup and readiness probes
write a row and roll it back, because taking the write lock alone succeeds
on such a file. A ledger that fails later holds every quorum with
`consensus_ledger_unavailable`, blocks delegated decisions with
`delegation_ledger_unavailable`, and turns `/ready` to 503
`quorum_ledger_unavailable` (both the quorum and the delegation ledger are
probed).
Tests: `tests/multi_agent_security/test_hardening.py`.

## Mutual checkpoints

`CounterpartyLedger(path, [their_public_key])` is one party's append-only
store of the other's checkpoints (`GET /v1/audit/checkpoint`):

- `accept(checkpoint)` keeps it if it is signed by the pinned key, intact,
  and does not go backwards from the last one held;
- `acknowledge(checkpoint, signer)` returns a signed `pv-checkpoint-ack/1`
  receipt built from the validated stored checkpoint, not the caller's count;
- `audit(export_lines)` recomputes every record hash from its contents, then
  checks the ordered export against every checkpoint held. Malformed JSON,
  duplicate keys, non-finite numbers and corrupt held checkpoints fail closed;
- `verify_acknowledgement(ack, checkpoint, holder_keys)` recomputes the
  checkpoint hash, requires matching record counts and verifies the holder's
  signature. This authenticates the holder's acknowledgement; authenticate
  the checkpoint's issuer separately when needed.

The raw-record hash algorithm matches `tools/verify_records.py`, with a
parity regression on real decision and execution exports. The standalone
verifier remains independent and unchanged. `audit` is a content-integrity
and checkpoint-completeness check, not a replacement for the standalone
verifier's full DRP schema, chain, lineage and per-record envelope checks.
Records after the newest held checkpoint have their content hashes checked,
but that checkpoint does not authenticate their origin or completeness.

## Minting re-checks the stored record

`/v1/authorize` reads the sealed decision back from the decision store.
Before using it, it recomputes the record's hash from the stored contents
and, when decision signing is on, verifies the stored signature over that
hash against the keys the server trusts. An edit to a stored record changes
its hash; a recomputed hash has no signature. A sealed expiry edited in the
database, a seal grafted from another decision, and a stored BLOCK flipped
to ALLOW are each refused with `AUTHORIZE_RECORD_HASH_MISMATCH`.

With decision signing off (`PV_RECEIPT_SIGNING_KEY` unset) only the hash is
checked, so someone who can write to the database and recomputes the hash
is not detected. The secure profile requires the signing key.
Tests: `tests/multi_agent_security/test_mint.py`.

## Conditions for relying on this for payments

These are an outside red-team reviewer's conditions after attacking the mint
path, recorded as given. `/v1/authorize` can be relied on for payments if
all of them hold:

1. Run the secure profile with signing on and `PV_OPERATIONS_FILE` pinned.
2. Use `required_agents` for payment agents.
3. Only the server can write to the database, **even with signing on**.
4. The payment receiver keeps its own record of used permits.
5. Every revocation is copied to every replica, and chain and approval
   lifetimes stay short.
6. Backups are always verified and restored with `--public-key`.
7. After any restore, re-apply revocations and treat the single-use records
   as reset (start the server with the `PV_MINT_NOT_BEFORE` value the
   restore prints).

### Why condition 3 holds even with signing on

Signing protects decision records: an edited record no longer mints. It does
not protect the tables that make a permit single-use, record an approval as
consumed, or record a grant as revoked. Someone who can write to the
database can delete those rows. The reviewer showed that one human approval
then yields two payment permits, that a decision which already minted mints
again, and that a revoked grant mints again. **This is open.** Closing it
means keeping that state somewhere a database writer cannot reach, or
signing and anchoring it outside the database; neither is built. Condition 4
(the receiver's own record of used permits) is the working defence: the
receiver kit, with a business transaction key declared for the payment
operation (ADR 0030), refuses a second permit for the same transaction with
409 whatever the agent side minted. ADR 0039 (proposed) makes that the
control of record for payments and lists what it does not cover, notably
operations without a business key and revocations stored in the database.

### Restoring an older backup

A restore proves the target equals the backup, not that the backup is the
latest state. Restoring a genuine, correctly signed older backup drops every
revocation, consumed approval and minted-permit record made after it, and
`/v1/verify` then reports the chain intact, because it is. The restore tool
now says this and prints a `PV_MINT_NOT_BEFORE` value; with it set, no
decision sealed before the restore mints. An approval issued before the
restore can still be used once more until it expires, and a lost revocation
stays lost until it is re-applied by hand.

### Also open

- With signing off, someone with database access can plant a whole fake
  allow record that passes `/v1/verify` and mints. They cannot forge the
  permit's own signature.
- `/v1/verify` re-reads stored records on every call and recomputes their
  hashes, so an in-place edit is seen without a restart. It does not see
  records removed from the end (that needs a checkpoint), and with signing
  off it does not see a record rewritten with its hash recomputed. Its
  response now states both under `not_verified`.
- `required_for` folds case, width and whitespace. Names that differ in
  plain letters or punctuation, such as `crm_read_contact` or
  `crm..read_contact`, are different names: they are outside the rule and
  mint after one approval. Only `required_agents` and `PV_OPERATIONS_FILE`
  close that.

Not verified by that review or by the authors: real multi-host replicas,
PostgreSQL under attack, the Rust build, the sandbox itself, and the
`pv approve`/`pv wrap` flow.

## What this layer does not do

- **Delegation never grants.** On `/v1/decide` it narrows what an agent's
  own grant allows. It is checked inside the authorization level; the
  precedence order is unchanged.
- **`max_amount` is per action.** Cumulative spend stays with the grant
  ledger. Limits on other arguments (a payee allow-list, for instance) are
  not expressible in a chain yet.
- **Revocation is per server, from its own file.** Each replica reads its
  own copy of `PV_DELEGATION_FILE`. A replica that has not been given the
  updated file does not know about a revocation, at decision or at mint.
  Nothing distributes the file; that is the deployment's job. Revoking a
  link hash does not stop its signer issuing the same grant again, which is
  what `revoked_agents` is for. Short expiries remain the dependable control.
- **Revocation does not recall a permit already minted.** A permit minted
  before a revocation lives out its own lifetime, which is capped at the
  chain's expiry.
- **A change is detected by the file's modification time and size.** An
  edit that changes neither is not seen until the next one that does.
- **A presentation's freshness rests on clocks.** Its lifetime is at most
  120 seconds plus 30 seconds of skew; its single use rests on the ledger.
- **The signing key is the holder.** A model that can reach the key can
  present. Keep it in a broker the model cannot read.
- **Independence is declared, not measured.** The rule runs over what the
  operator wrote in the roster. Labels are normalized (case, whitespace,
  compatibility forms) and non-ASCII labels are refused, so spelling
  variants and look-alikes cannot inflate the count. Nothing checks that a
  voter runs the model it is labelled with, or that two differently
  labelled voters are independent in fact.
- **Clock skew beyond 300 seconds** between replicas can still let a spent
  vote be used again.
- **Checkpoint exchange is not automated.** There is no transport, schedule
  or dispute process; the ledger and receipts are the building blocks.
- **Prompt injection spreading from agent to agent is not addressed.**
- **Keys are identities.** Every guarantee here is about which pinned key
  signed, not about how the agent behind it behaves.
