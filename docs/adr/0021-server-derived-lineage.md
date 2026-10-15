# 0021: Multi-agent dual control runs on server-derived lineage, not a caller-chosen id

Status:     accepted (PR 1 identity, PR 2 lineage for dual control, PR 3 signed lineage evidence)
Date:       2026-10-15
Pinned by:  tests/test_lineage_dual_control.py::test_split_execution_ids_no_longer_bypass;
            tests/test_lineage_dual_control.py::test_filler_events_cannot_evict_the_initiate;
            tests/test_lineage_dual_control.py::test_junk_ids_cannot_evict_other_agents_flow;
            tests/test_lineage_dual_control.py::test_distinct_checker_approves_exactly_once;
            tests/test_identity_normalization.py::test_maker_cannot_approve_as_case_variant;
            tests/test_lineage_evidence.py::test_exported_flow_verifies_offline_with_signatures;
            tests/test_lineage_evidence.py::test_concurrent_writes_never_fork_the_chain

## What forced the decision
Cross-agent behavioural invariants (CABI, ADR 0018) correlate a multi-agent
flow by the `execution_id` the caller declares, in a bounded in-memory LRU
shared by every agent. The 2026-10 security review confirmed three ways for
one agent to both initiate and approve the same payment:

1. initiate under execution id A, approve under execution id B;
2. push 500 filler events into the window so the initiate is evicted;
3. open 1,000 junk execution ids so the whole window (any agent's) is evicted.

It also confirmed that `Maker-1` and `maker-1` were two identities to every
comparison. A control an agent can route around by choosing a string is not
a control.

## The decision
**Identity (PR 1).** `agent_dna.identity.fold_agent_id` (NFKC, casefold,
NFKC, strip) is the comparison form for maker != checker, approval
separation of duties, loop detection at `/v1/authorize`, and API key
loading. A key file whose names collide after folding refuses to load.

**Lineage (PR 2).** `agent_dna.lineage.LineageLedger` keeps one row per
decision in the decision store's SQLite file: the folded agent, capability,
intent (initiate / approve / other), verdict and flow. A flow is never named
by the caller; it is rooted at the first decision's `record_hash` and joined
only by referencing a decision the server already recorded:

- `lineage.approves = <record_hash>` on an approve-type decide names the
  initiate being approved. The maker is read from the server's row.
- `lineage.parent_record_hash` continues an existing flow.
- Unknown fields are refused (422), so a flow id cannot be supplied.

With `PV_LINEAGE=enforce`, after the engine and CABI, each of these BLOCKs
with `triggered_by = "lineage_invariant"`:

| Finding | Meaning |
|---|---|
| `LINEAGE_APPROVE_UNBOUND` | approve-type action without `lineage.approves` |
| `LINEAGE_REFERENCE_UNKNOWN` | the referenced decision was never recorded |
| `LINEAGE_APPROVE_TARGET_NOT_INITIATE` | the reference is not an initiate |
| `LINEAGE_MAKER_EQUALS_CHECKER` | the approver is the initiator (folded ids) |
| `LINEAGE_INITIATE_ALREADY_APPROVED` | a UNIQUE claim already exists for that initiate |

Lineage is escalate-only: it never relaxes a verdict, and the one-approval
claim is taken only when the final verdict is ALLOW. Rows persist across
restarts and are never evicted. `PV_LINEAGE=shadow` records rows and reports
findings in the response without changing any verdict; `off` (default)
leaves behaviour unchanged. CABI keeps running as an additional check.

**Evidence (PR 3).** Each lineage row is also a sealed `pv-lineage-event/0.1`
event: flow, seq, prev_event_hash, record_hash, agent, capability, intent,
verdict, references and time. `event_hash = sha256("pv-lineage-event/0.1\n"
|| canonical JSON)`; the domain prefix keeps an event hash from ever
equalling a decision or manifest hash signed by the same key. The chain
position is assigned inside `BEGIN IMMEDIATE`, so concurrent decides in one
flow cannot fork it. When the receipt signer is configured each event hash is
signed (Ed25519). `GET /v1/flows/{flow_id}` (audit or full scope) exports a
flow; `tools/verify_lineage.py` checks it with the standard library and
PyNaCl only: field set, hashes, gap-free seq, the chain, signatures from
`--trusted-key`, and the dual-control rule itself (no self-approval, at most
one ALLOWed approval per initiate). Rows recorded before PR 3 are exported
unsealed and the verifier refuses them.

**Deployment (PR 4).** Under `PV_SECURE_PROFILE=1` lineage defaults to
`enforce` and the server refuses to start with `off` or `shadow`.
`GET /v1/runtime` reports `composition.lineage` (`enforced`, `shadow` or
`not_attached`). `tools/verify_deployment.py` checks those claims against a
running server and then probes behaviour: an unbound approval and a
self-approval must both be refused with `triggered_by=lineage_invariant`.
A deployment may claim enforced maker != checker only for covered flows on
a server that passes this verifier.

## What this costs us
- One extra SQLite read per decide and one write per recorded decision.
- Integrations must pass `lineage.approves` on approval steps. Shadow mode
  exists so operators can see who would be blocked before enforcing.
- The sealed decision record does not carry the lineage edge; the link
  lives in the signed lineage event. Deleting a whole flow's tail is not
  detectable from the export alone (same limit as ADR 0004 exports).
- The lineage row is written after the decision record, outside its
  transaction. A crash between the two leaves a sealed decision with no
  lineage row; a later approval referencing it fails closed
  (`LINEAGE_REFERENCE_UNKNOWN`).

## What would make us revisit
- Loop detection fed from server lineage instead of caller events (PR 4).
- Signed attenuating delegation (ADR 0022) changes who may join a flow.
