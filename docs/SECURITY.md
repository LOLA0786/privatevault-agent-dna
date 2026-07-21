# Security Model

PrivateVault Agent DNA — Decision Security Runtime
Status: pre-certification (no SOC 2 / ISO 27001 — see
`WHAT-WE-DO-NOT-CLAIM.md`). This document states what the system
defends against, what it assumes, and what it explicitly does not
cover. Claims here follow the repository rule: each traces to a named
test or is marked as an assumption.

## 1. What the system is, in security terms

A deterministic policy decision point (PDP) placed in front of agent
actions, plus a tamper-evident evidence layer. Two security goals:

- **G1 — Pre-execution enforcement.** No action reaches its executor
  with an `allow` unless it passed every deterministic level of the
  precedence contract (`spec/contracts/precedence-order.json`,
  hash-pinned, CI-verified — `test_precedence_contract.py`).
- **G2 — Non-repudiable evidence.** What was decided, by which rule,
  and what subsequently executed is reconstructible and
  tamper-evident from the records alone, verifiable with one
  standard-library file (`tools/verify_records.py`).

## 2. Threat model

### Adversaries considered

| ID | Adversary | Capability assumed |
|----|-----------|--------------------|
| T1 | Compromised or drifted agent | Submits arbitrary actions/arguments at any rate |
| T2 | Prompt-injected agent | As T1, plus adversarially crafted content in arguments |
| T3 | Log tamperer | Read/write access to stored decision records after the fact |
| T4 | Result forger | Reports fabricated execution outcomes |
| T5 | Colluding agent subset | Coordinated votes/interactions in multi-agent flows |
| T6 | Key-holding over-reacher | Valid API key, attempts actions beyond its scope |
| T7 | Internal fault | Our own bugs: throwing scorers, missing evidence, races |

### Defenses, each with its test

- **T1/T2** → deterministic precedence: invariants, customer policy,
  grants, circuit breakers evaluate structured fields (capability,
  arguments, evidence), not natural language; a deterministic DENY is
  final (`test_decision_engine.py`, `test_policy_checker.py`,
  `test_capability_grants.py`, `test_circuit_breaker.py`,
  `tools/run_adversarial.py` — 11/11).
- **T3** → per-record SHA-256 over canonical content + per-agent hash
  chaining; edits, deletions, reorders break verification
  (`test_p0_audit.py`, `test_spec_vectors.py`). Optional Ed25519
  receipt signatures (`test_signer.py`, `test_api_signing.py`).
- **T4** → execution events hash-anchored to the authorizing decision;
  divergence (blocked-but-ran) is detected as ENFORCEMENT DIVERGENCE
  (`test_anchor_provenance.py`, `test_execution_feedback.py`).
- **T5** → consensus requires signed votes (HMAC/Ed25519,
  constant-time comparison), expiry, minimum distinct voters,
  Byzantine-resilient thresholds; unsigned/expired votes never count
  (`test_secure_quorum.py`, `test_weighted_quorum.py`); cross-agent
  interaction contracts (`test_multi_agent_invariants.py`).
- **T6** → API keys SHA-256-hashed at rest; scopes enforced
  server-side; an audit-scoped key can never exercise enforcement
  authority (`test_apikeys_scope.py`, `test_api_audit_scope.py` —
  this property regressed once during development, was caught, fixed,
  and is regression-locked).
- **T7** → fail-closed: any internal exception in the decision path
  becomes a deterministic BLOCK (`engine_fault`), never a silent
  pass; missing evidence causes a visible SKIP, never an implied
  pass; non-finite scores are guarded (`test_fail_closed.py`,
  `test_api_fail_closed.py`, `test_nonfinite_guard.py`); multi-writer
  SQLite safety under concurrency (`test_multi_writer_safety.py`,
  `test_connection_thread_safety.py`); restart restores chain state
  (`test_restart_survival.py`).

## 3. Trust assumptions (the honest part)

- **A1 — Interposition.** The runtime only governs actions routed
  through it (HTTP API, MCP connector, or adapters). An executor with
  a direct side channel to the outside world is out of scope; the
  audit layer will, however, expose the divergence if outcomes are
  reported (G2 catches what G1 cannot reach).
- **A2 — Host integrity.** The host running the PDP and the signing
  key (`PV_RECEIPT_SIGNING_KEY`, environment/file-based, never
  committed) are trusted. A root-level attacker on this host defeats
  G1; already-emitted signed records remain verifiable, and forward
  tampering of the chain remains detectable by external copies.
- **A3 — Policy authorship.** Customer policies are trusted input.
  A malicious policy author can weaken L2 for themselves; they cannot
  weaken L0/L1 or forge records.
- **A4 — Advisory layer is untrusted by design.** The learned drift
  signal can only escalate. Its quality is separately validated and
  sealed (`pv-validation/1`, `docs/VALIDATION-MATH.md`); a missing or
  failed validation report never loosens enforcement
  (`test_validation_guard.py`).

## 4. Residual risks (known, open)

- Availability: fail-closed converts some faults into denial of
  service for agent traffic. This is the chosen trade; deploy with
  shadow mode first and monitor `engine_fault` rates.
- No formal verification: determinism claims are replayability
  claims backed by tests, not proofs (`WHAT-WE-DO-NOT-CLAIM.md §
  Determinism`).
- MCP transport enforcement is not yet load-tested under high
  concurrent client counts.
- Behavioral baselines are calibrated on synthetic traces until a
  customer pilot trace is wired; this bounds the advisory layer's
  value, not the deterministic layers' correctness.
- Signing-key rotation is manual (`rotate_key` stub); compromise of
  the current key allows forging *new* records until rotated —
  historical chain segments verified against the old public key
  remain intact.

## 5. Reporting a vulnerability

Email **security@privatevault.ai** with reproduction steps. No bug
bounty is offered at this stage; we commit to acknowledgment within
72 hours, a fix-or-mitigation plan within 14 days for confirmed
issues in the enforcement or audit path, and credit (if desired) in
the changelog. Please do not open public issues for exploitable
findings before a fix is released.
