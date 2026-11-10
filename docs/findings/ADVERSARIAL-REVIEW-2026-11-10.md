# Adversarial review: enforcement core, verifier, consensus (2026-11-10)

Second pass on `main` at `48df8c3` (v0.4.0). Scope: `agent_dna/decision.py`
and the levels it calls, `tools/verify_records.py` with the signer, and
`agent_dna/consensus/`. Every finding was reproduced against the real code
before it was written down. None lets an unauthenticated caller turn a BLOCK
into an ALLOW directly.

## Status

| # | Severity | Area | Finding | Status | Pinned by |
|---|---|---|---|---|---|
| F-1 | High | Core | A `require_approval` policy rule converts a hard BLOCK below it into an approvable hold | **Fixed** | `tests/test_policy_hold_is_additive.py` |
| F-2 | High | Verifier | Deleting records passes verification, in signed mode | **Fixed** (needs a checkpoint held outside the operator) | `tests/test_checkpoint_completeness.py` |
| F-3 | High | Consensus | The submitter of a vote set also chooses the threshold, the weights and the action it applies to | **Fixed** | `tests/test_consensus_checker.py`, `tests/test_api_completeness_and_quorum.py` |
| F-4 | Medium | Consensus | A signed REJECT can be re-read as an APPROVE on another action | **Fixed** | `tests/test_secure_quorum.py::test_vote_payload_has_one_reading` |
| F-5 | Medium | Core / verifier | A hold that was ignored and executed is not reported as divergence | Open | |
| F-6 | Medium | Core | L0's mandatory evidence is whatever the caller types | Open | |
| F-7 | Low | Verifier | Chain-only mode passes a fully rewritten history without saying origin is unverified | **Fixed** | `tests/test_checkpoint_completeness.py::test_chain_only_mode_says_origin_is_not_verified` |
| F-8 | Low | Verifier | `1e999` bypasses the non-finite check | **Fixed** | `...::test_overflowing_number_is_rejected_like_infinity` |
| F-9 | Low | Verifier | A non-object line ends in a traceback, not a verdict | **Fixed** | `...::test_non_object_line_fails_with_a_verdict` |
| F-10 | Low | Signer | One key signs five artifact types with no domain separation | Open (checkpoints are tagged; existing artifact types are not) | |

What the fixes leave open is listed under each finding and in
`docs/WHAT-WE-DO-NOT-CLAIM.md`. The sections below describe each finding as
it was found, then what changed.

## F-1 (High): a stricter-looking policy rule weakens enforcement

`decide_from` returns at the first level that fires. Customer policy (L2)
sits above consensus, authorization, economics and drift, and a policy hold is
one of the two triggers an approval can satisfy
(`APPROVABLE_TRIGGERS = {"policy", "authorization"}`). So when a policy rule
with outcome `require_approval` matches, nothing below it is evaluated, and
the hold it returns is approvable regardless of what the lower levels would
have said.

Reproduced with one rule, "payments over 10,000 need sign-off", and a valid
approval from a pinned approver:

| Situation | Without the rule | With the rule + approval |
|---|---|---|
| Secure profile, agent has no grant at all | BLOCK (`authorization`) | **ALLOW**, `grant_id=None` |
| Granted, drift score 0.99 | hold, "not satisfiable by an approval" | **ALLOW** |
| Granted, cost 900x historical average | hold (`economics`), not approvable | **ALLOW** |

The first row contradicts the comment at `decision.py:617`: "a hard refusal
that no approval can turn into an ALLOW". The approver is real, but they are
shown "large payment needs sign-off", not "this agent holds no grant" or
"drift 0.99"; the sealed record says `triggered_by: approval` and carries no
trace of the levels that never ran.

The README property "a deterministic DENY is final" survives for L0, L1 and
policy `block` rules. It does not survive for the secure-profile ungranted
BLOCK, which is decided after `decide_from` returns.

**What changed.** A policy `require_approval` is additive. The levels below
it still run in their existing order; if one fires, the hold carries it
(`also_fired`, and `also held by <level>` in the sealed reason), and an
approval lifts the hold only when every level that fired is approvable. The
secure profile's ungranted BLOCK is applied whichever level named the hold,
so a consensus shortfall above authorization no longer downgrades it either.
The three rows above now return BLOCK, hold and hold.

Left as it was, deliberately: when no policy rule fires, the lower levels
are still first-match, so an authorization hold remains approvable even
though drift would also have fired for an unfamiliar capability. That is
ADR 0020's approval flow, and ten existing tests depend on it. If drift
should veto an approval there too, it is a product decision, not a bug fix.

The property is pinned over all 16 combinations of grant, drift, economics
and secure profile: adding the rule never makes the verdict more permissive.

## F-2 (High): record deletion is not detected

Tested against a real signed export, with envelopes and the trusted key
supplied, which is the strongest mode the verifier has. The untouched export correctly fails with ENFORCEMENT
DIVERGENCE (a BLOCK whose execution reported `ok`). Then:

| Edit to the export | Lines removed | Verdict |
|---|---|---|
| Delete the one execution event showing the BLOCK ran, and its envelope | 1 | **PASS** |
| Truncate that agent's chain from the BLOCK onward | 6 | **PASS** |
| Delete every record of that agent | 12 | **PASS** |
| Delete the head of the chain up to the BLOCK | 8 | FAIL (lineage parent missing) |

Causes: chains are per agent with no commitment to the head, there is no
commitment to which agents exist, and execution events hang off their decision
individually, so removing one leaves nothing dangling. The README table row
"Delete or reorder records: per-agent chain break" holds only for interior
deletions. `export_manifest.py` signs the bytes of an export after it is
produced; it does not help when rows are removed from the store first, and
`verify_records.py` does not read it.

**What changed.** `GET /v1/audit/checkpoint` (and
`python -m agent_dna.checkpoint`) returns a signed `pv-checkpoint/1`: record
count, decision and execution counts, a running SHA-256 over every record
hash in append order, and each agent's chain head. The signature is taken
under its own tag, so a record envelope cannot be presented as a checkpoint
signature. `verify_records.py --checkpoint` requires the export's first
`record_count` records to reproduce it. All three passing rows above now
fail with `INCOMPLETE EXPORT`; without a checkpoint the verifier prints
`completeness : NOT VERIFIED`.

No record format change was needed, so DRP 0.1 and 0.2 exports verify as
before. `tools/verify_records.py` did change: sync the `drp-spec` copy.

Still open: a checkpoint protects only records that existed when it was
taken, and only if someone other than the operator keeps it. Scheduled
fetching into customer-held storage, or a transparency log, is not shipped.

## F-3 (High): consensus parameters come from the party being checked

`ConsensusChecker.check` reads `threshold`, `trust_scores`, `action_id` and
the votes from the same `evidence["consensus"]` object, which arrives in the
request body:

- One vote from the lowest-trust voter with `threshold: 1e-9` clears quorum.
- At the default threshold, one APPROVE against three REJECTs clears quorum
  when the submitter declares that voter's trust as 1.0.
- REJECT votes subtract nothing, so withholding them costs nothing. There is
  no roster, so the checker cannot know who did not vote.
- `action_id` is a free string, not derived from the action under decision.
  Votes cast for "approve-coffee-order" cleared three unrelated checks in a
  row; nonces are tracked in a `SecureQuorum` built fresh on every call.

Separately, on the shipped server: `register_key` is
called only from examples, so the production process holds zero vote keys. A
unanimous, correctly signed quorum returns 202 `consensus`; the same request
with the evidence left out returns 200. On the live path L3 cannot confirm any
vote and is skipped by omission, so it currently adds no enforcement. Votes
are HMAC with a shared secret, so the verifier can also forge any vote.

`docs/WHAT-WE-DO-NOT-CLAIM.md` says consensus is "wired into the live
precedence order" with signed, trust-weighted voting. As written, that
overstates it.

**What changed.** `PV_CONSENSUS_FILE` pins the roster, each voter's weight and
Ed25519 public key, the threshold, and `required_for` capability prefixes.
The threshold must exceed half the total weight unless the operator opts
out, so withheld votes cannot matter. A `threshold` or `trust_scores` field
in the request is refused. Votes are `pv-vote/2`: signed with the voter's
own key, so the service cannot forge them, over an action id the service
recomputes from the agent, capability and arguments under decision. A
cleared quorum cannot be presented twice to the same process. With no
roster, supplied votes are held and the composition manifest says so. An
invalid roster refuses startup.

Follow-up, done: `PV_CONSENSUS_NONCE_DB` names a SQLite ledger shared by
every replica, so a cleared quorum is single-use across replicas and
restarts (`tests/multi_agent_security/test_quorum_hardening.py`), and a
PostgreSQL ledger is used automatically with `PV_DATABASE_URL` for replicas on
separate hosts (`tests/multi_agent_security/test_hardening.py`).

## F-4 (Medium): delimiter injection in the vote payload

`vote_payload` is `"|".join(fields)` with no escaping. A reviewer's signed
REJECT on action id `wire-9M|fraud|APPROVE|h` is byte-identical to an APPROVE
by the same reviewer on action `wire-9M` with message hash
`h|fraud|REJECT|m`. The test replays it and the checker counts it as an
approval. Whoever proposes the action id controls this.

**What changed.** The `pv-vote/1` payload is a JSON array and `pv-vote/2` is
a JSON object; each signed string has one parse.

## F-5 (Medium): an ignored hold is invisible

On the live API: decide returns 202 `require_approval`; the caller executes
anyway and posts outcome `ok` with `dispatched: true`; the server accepts it
(200) and `/v1/divergent` stays empty. `find_divergent` and verifier check 9
both test only `block` + `ok`. An agent ignoring a hold is a more likely
failure than one ignoring a block.

Fix: treat `require_approval` + `ok` as divergence in both places. An
approved action already gets its own ALLOW record, so there are no false
positives.

## F-6 (Medium): L0 evidence is self-asserted

For a sensitive capability with no evidence, L0 returns 403
`missing_required_evidence`. Resending with
`user_request.canonical_target`, `planner.canonical_target` and
`approvals: {"required": true, "token_present": true}` typed into the request
clears L0. The authority check's pass reason is "approval token verified";
no token is examined. The same applies to `enterprise_state` and `economics`
evidence.

This is sound only if the caller of `/v1/decide` is a harness the agent
cannot influence. The MCP `pv_decide` tool makes the agent the caller. The
threat model does not state the assumption.

Fix: state the trust boundary in `THREAT-MODEL.md`; record evidence
provenance in the sealed record; for authority, require an artifact the
server verifies (the ADR 0020 approval bridge already does this) in place of
a boolean.

## Low

- **F-7.** In chain-only mode a history with the BLOCK rewritten to ALLOW and
  every hash recomputed returns `VERDICT: PASS` with no caveat. Expected for
  an unkeyed chain, but the output should say `ORIGIN NOT VERIFIED` so the
  verdict is not misread.
- **F-8.** `parse_constant` catches the literals `NaN` and `Infinity` only.
  `"drift_score": 1e999` parses to `inf` and passes check 1. Add a
  `parse_float` hook that rejects non-finite results.
- **F-9.** A line that is valid JSON but not an object (`[1,2,3]`) raises
  `AttributeError`. Exit code is 1, so it fails closed, but there is no
  verdict line for tooling to parse.
- **F-10.** The receipt key signs decision hashes, execution hashes, lineage
  event hashes, export manifest hashes and key rotations, all as a bare
  64-hex string. Not exploited here; found by reading. Prefix a type tag
  (`pv-decision/1:` and so on) before signing so a signature made for one
  artifact type can never be presented as another.

## What held

- Policy `block` and L0/L1 BLOCKs were not lifted by a valid approval.
- Deleting the head of a chain is caught by the lineage parent check.
- Enforcement divergence is caught on an untouched export.
- Malformed consensus evidence (wrong types, zero threshold, trust above 1)
  raises in the checker; `DecisionEngine.decide` turns any exception into an
  `engine_fault` BLOCK.
- By reading, not by test: amount coercion rejects negative, non-finite,
  boolean and over-ceiling values; a budgeted grant with no amount fails
  closed; duplicate JSON keys and untrusted keys are rejected by the verifier.

## Not covered

PostgreSQL store, Rust signer, permit minting and the receiver gate, the MCP
connector, the Claude Code plugin, cross-agent invariants (CABI), and the
loop detector.

## What to do next

1. F-5: treat `require_approval` + `ok` as divergence in
   `decision_graph.find_divergent` and verifier check 9.
2. F-6: state the caller trust boundary in `THREAT-MODEL.md`, record
   evidence provenance in the sealed record, and replace
   `approvals.token_present` with an artifact the server verifies.
3. F-2 follow-up: ship the scheduled checkpoint fetch (a CronJob in the Helm
   chart writing to customer-held storage).
4. F-3 follow-up: done (SQLite and PostgreSQL shared ledgers).
5. F-10: tag the remaining signed artifact types in the next DRP version.
