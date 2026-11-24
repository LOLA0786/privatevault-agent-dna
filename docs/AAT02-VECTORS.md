# AAT -02 delegation vectors

PrivateVault's delegation, pv-delegation/2 (ADR 0042), exported as
conformance vectors in the layout of the AAT -02 test suite, so they can be
compared with the drafts in tenuo-ai/tenuo's
[constraint-comparison](https://github.com/tenuo-ai/tenuo/tree/main/ietf/constraint-comparison).
Nothing has been submitted.

| File | What it is |
|---|---|
| `vectors/aat02/pv-delegation-2.json` | The suite: 35 vectors |
| `tools/gen_aat02_vectors.py` | Writes it, byte for byte, from PrivateVault's own `issue_link` and deterministic test keys |
| `tests/test_aat02_vectors.py` | Replays every vector through `within_scope` and `verify_chain`; any disagreement fails CI |
| `vectors/aat02/aat-analogues.json` | The same scenarios as 32 real AAT -02 vectors, in the AAT suite's layout |
| `tools/check_aat02_analogues.py` | Builds them with the AAT reference verifier's own helpers and checks the suite's AAT column against it |
| `tests/test_aat02_analogues.py` | Keeps the analogues in step with the suite; with `TENUO_DIR` set, rebuilds them and reruns the reference verifier |

## Format

The layout is that of the
[229-vector AAT -02 suite](https://github.com/tenuo-ai/tenuo/blob/main/tests/vectors/aat-jws-vectors.json)
in tenuo-ai/tenuo, which CleiMesh's `cleimesh-aat` replays in its draft -02 test: suite-level
`spec`, `conventions`, `params`, `keys` and `trust_anchors`, then `vectors`,
each with `id`, `title`, `description`, `notes`, `now`, `tool`, `args`,
`args_json`, `policy`, `params`, `replay_state`, `chain` and `expected`.

The tokens are not AAT JWS. Each chain is real pv-delegation/2 links, and
each link carries its AAT -02 view beside it. This is the property-level
route the AAT interop guide gives an implementation in another format.

- `expected` is PrivateVault's verdict, `PERMIT` (accept) or `DENY`
  (reject), and a stable reason code.
- `aat_02` is the verdict and Section 8 step that AAT's reference verifier
  gives the same scenario, built as AAT -02 tokens. All 32 agree; 3 vectors
  have no AAT counterpart and say `n/a` (a cumulative budget, revocation).
- `interpretations` gives each draft's reading where they differ.

## Claim mapping

| AAT -02 | pv-delegation/2 |
|---|---|
| `par_hash` | The link's parent field: SHA-256 over `pv-delegation/1:` and the parent's canonical JSON without its signature, in hex. The view re-encodes it base64url without padding; AAT hashes a JWS signing input instead. |
| `del_depth` | Not carried: the link's position in the chain, 0 at the root |
| `del_max_depth` | `del_depth` plus the link's `max_depth`, which counts remaining hops |
| `authorization_details` tools | `capabilities` |
| `one_of` | `constraints`: a value list per argument; every link's constraints apply |
| None | `budget`, shown as `pv_budget` |

## Coverage

| Area | Vectors | PrivateVault |
|---|---|---|
| Every limit narrows; limits kept equal; a root alone | PV.1 to PV.3 | Accept |
| Widened or dropped budget | PV.4, PV.5 | Reject |
| Widened scope; an added argument value; a dropped constraint | PV.6 to PV.8 | Reject |
| A constraint on an argument the parent never named; an argument no link names | PV.9, PV.10 | Accept, unlike AAT |
| Depth past the limit; a raised or dropped limit; a terminal root | PV.11 to PV.14 | Reject |
| Depth counting at limits 3 and 8 | PV.15 to PV.18 | See below |
| Wrong, missing, spliced or reordered `par_hash`; one on the root | PV.19 to PV.23 | Reject |
| A replayed, revoked or expired link; a forged signature, a wrong key, an unpinned root, a field changed after signing | PV.24 to PV.30 | Reject |
| A child that outlives its parent | PV.31 | Reject |
| A swapped or omitted constrained argument; a tool outside scope; a presenter that is not the leaf | PV.32 to PV.35 | Reject |

## Depth counting

The comparison names this case CC-1.

- **AAT -02:** the root has `del_depth` 0, so a limit of N admits depths 0 to
  N, which is N + 1 tokens. A limit of 8 admits nine.
- **asor -03:** a limit of N admits N tokens. A limit of 8 admits eight.

PrivateVault has two rules, and they count differently:

- **The limit a link carries** counts delegations, as AAT does. A root limit
  of 3 admits four links (PV.15) and refuses a fifth (PV.16).
- **The fixed cap** (`MAX_DEPTH = 8` in
  `agent_dna/multi_agent_security/delegation.py`) counts links. A chain has at
  most eight, whatever its limits say.

At a limit of 8 the cap decides. PrivateVault admits eight tokens, as asor
does (PV.18), and refuses the nine AAT admits (PV.17, `chain_too_deep`), a
chain AAT's reference verifier admits. So PrivateVault follows AAT for the limit a link carries, and its deepest chain
is depth 7, one short of AAT's `MAX_DELEGATION_DEPTH` of 8. A valid AAT chain
at depth 8 does not verify here. Closing that gap means counting the cap in
delegations, which allows nine links: a change of behaviour that needs its own
ADR, and it is not made here.

## Arguments no constraint names

The comparison names this case CC-3. AAT denies an argument that a
constraint map does not name, unless the map has `"*"`. So a child that
constrains a new argument widens (4p2), and an unnamed argument at the leaf
is denied (6b). PrivateVault checks only the arguments a link names and
leaves the rest free, as asor's "unbounded" does. It accepts both (PV.9,
PV.10); AAT's reference verifier denies them, at 4p2 and 6b.

## Other differences

- **Replay.** PrivateVault has no per-link identifier check like AAT's
  duplicate `jti` step (2c). A link presented twice is still refused: its
  second copy is not signed by the agent then holding the authority (PV.24,
  `holder_mismatch`).
- **Order of checks.** PrivateVault checks narrowing before the signature,
  and AAT the other way round. The verdict is the same; the reason for a
  forged link that also widens is the widening.
- **Revocation.** PrivateVault revokes by link hash and by identity; the -02
  verification algorithm leaves revocation out (PV.25 is `n/a` for AAT).
- **Budget.** Cumulative and charged when a decision is allowed, not by
  `verify_chain`. These vectors cover only that a child may not raise or
  drop it.

## Not covered

- **AAT's encoding:** JWS and JOSE headers, `typ`, the algorithm allowlist,
  `crit`, compact serialization, CBOR twins and size limits.
- **Holder keys and proof of possession:** AAT binds each hop to the parent's
  `cnf.jwk` and each call to a PoP JWT (step 7). PrivateVault pins keys by
  identity and proves the holder elsewhere (`authorize`, `DelegationGate`).
  PV.35 covers only that the presenter is the leaf.
- **Constraint types beyond a value set:** `range`, `wildcard`, `exact`,
  `"*"`, required and optional.
- **Other checks:** `aud`, nonces, clock-skew boundaries, `max_amount`
  ceilings, budget charging, revoked identities, and version 1 links under a
  version 2 parent.
- **asor readings:** they come from the comparison's README, which asor's
  author has not reviewed. Only the AAT column is checked by running code.
- **Other AAT implementations:** the analogues are in the layout CleiMesh's
  draft -02 test reads, but no AAT implementation other than the reference
  verifier has run them.

## Regenerate and replay

```bash
uv run python tools/gen_aat02_vectors.py
uv run python tools/gen_aat02_vectors.py --check
uv run python -m pytest -q tests/test_aat02_vectors.py
```

The first writes the suite, the second fails if the committed suite is
stale, and the third replays it.

To check the AAT column, with a checkout of tenuo-ai/tenuo:

```bash
uv run python tools/check_aat02_analogues.py --tenuo ../tenuo
uv run python tools/check_aat02_analogues.py --tenuo ../tenuo --write
```

The first builds every scenario AAT can express as AAT -02 tokens, with the
helpers of AAT's reference verifier ([gen_vectors.py](https://github.com/tenuo-ai/tenuo/blob/main/ietf/vectors/gen_vectors.py)), and runs
its Section 8 verifier. The second also rewrites the analogues. With
`TENUO_DIR` set, `tests/test_aat02_analogues.py` does the first. The keys are test keys: each Ed25519 seed is
SHA-256 of `pv-aat02-vectors/` followed by the party's name.
