# Evidence Integration Contract

**What this is:** the exact shape of the `evidence` dict every precedence
level in the composed engine consumes. This is the integration surface —
whatever retrieves enterprise context (a data warehouse query, a RAG
pipeline, a knowledge graph, a manual API call) writes to this contract.
PrivateVault does not retrieve enterprise data; it consumes structured
evidence, however the caller obtains it.

**Status discipline:** every key below is marked SHIPPED (a real
precedence level reads it today) or PLANNED (named as a target, no
consumer exists yet). Do not build a connector against a PLANNED key
until it has a real consumer — see `docs/WHAT-WE-DO-NOT-CLAIM.md`.

---

## Top-level shape

```python
evidence: dict = {
    "user_request": {...},  # SHIPPED — L0
    "planner": {...},  # SHIPPED — L0
    "approvals": {...},  # SHIPPED — L0
    "enterprise_state": {...},  # SHIPPED — L0
    "consensus": {...},  # SHIPPED — L3 (consensus; contract v4.0)
    "economics": {...},  # SHIPPED — L4 (economics)
}
```

Any key omitted entirely means "the corresponding check is SKIPPED, not
failed" — see each level's evidence-honesty note below. This is not a
detail; it's the core guarantee: absence of evidence never silently
counts as evidence of safety.

---

## `user_request` / `planner`  — SHIPPED (L0, identity_preservation)

Proves the action the tool is about to execute matches what the user
actually asked for and what the planner actually planned — the
injected-instruction / target-redirection defense.

```python
"user_request": {"canonical_target": str},   # what the user asked for
"planner":      {"canonical_target": str},   # what the planner decided
```

Consumer: `agent_dna/uaal_layer.py` → `InvariantEngine` (vendored from
UAAL's EAV engine). Both must be present and equal for the check to run;
either missing → check SKIPPED, not passed.

---

## `approvals`  — SHIPPED (L0, authority_preservation)

```python
"approvals": {
    "required": bool,
    "token_present": bool,   # only checked if required=True
}
```

If `required=False`, this check passes trivially. If `required=True` and
`token_present` is absent, the check is SKIPPED (evidence-honest — an
unverifiable approval requirement is never silently treated as met).

---

## `enterprise_state`  — SHIPPED (L0, monetary_conservation + enterprise_state)

The core fact-checking evidence — this is what catches amount tampering,
duplicate/replayed transactions, closed-account payments, unverified
payees.

```python
"enterprise_state": {
    "invoice_amount":  float,   # the SYSTEM OF RECORD amount — compared
                                  # against the agent's claimed amount
    "invoice_open":    bool,    # False -> payment against closed invoice
    "target_verified": bool,    # False -> unverified payee/counterparty
    "duplicate":       bool,    # True  -> replay/duplicate detected
}
```

Consumer: `agent_dna/uaal_layer.py`. Any subset may be supplied; each
missing field's corresponding check is individually SKIPPED — this
dict does not need to be fully populated to be useful.

**Integration note:** this is the field a core-banking, ERP, or
policy-engine connector would populate — e.g. "invoice_amount" pulled
live from Oracle/SAP, "target_verified" from a KYC/vendor-master check.
No such connector is built. This document exists so one can be built
correctly, later, against a stable contract.

---

## `consensus`  — SHIPPED (L3, contract v4.0)

```python
"consensus": {
    "action_id":     str,
    "threshold":     float,               # default 0.67
    "votes": [
        {"agent_id": str, "vote": "APPROVE" | "REJECT",
         "signature": str, "message_hash": str},
        ...
    ],
    "trust_scores": {agent_id: float},    # optional, default 0.5
}
```

Consumer: `agent_dna/consensus/checker.py`. Votes must be HMAC-signed
(see `agent_dna/consensus/signing.py`); an unsigned or forged vote
contributes zero weight, proven by `tests/test_secure_quorum.py`.

---

## `economics`  — SHIPPED (L4)

```python
"economics": {
    "estimated_cost_usd":       float,
    "historical_avg_cost_usd":  float,   # optional — enables cost-ratio check
    "business_value_usd":       float,   # optional — enables ROI-floor check
}
```

Consumer: `agent_dna/economics/cost_check.py`. Either sub-check runs
independently if its required fields are present; missing fields skip
that specific sub-check only.

---

## PLANNED — named, no consumer exists

These map to real-sounding enterprise requirements but have **zero
implementation** today. Listed here so a future connector isn't built
against a key nothing reads.

| Key | What it would need to prove | Blocker |
|---|---|---|
| `policy_version` | Agent used the *current* policy, not a stale cached one | No policy-versioning system exists |
| `compliance_documents` | Required compliance docs are present for this action | No document-completeness checker exists |
| `regulatory_context` | Action complies with latest applicable regulation | No regulation-tracking system exists |
| `hallucination_signal` | Agent's claimed facts match retrieved source data | No fact-grounding/RAG-verification layer exists |
| `manager_approval_chain` | A specific human approval chain was followed, not just "any" approval | `approvals.token_present` is boolean today, not a chain |

**Do not build a retrieval connector that populates these keys until a
precedence-level consumer for that key exists and is tested.** Populate
`enterprise_state`, `consensus`, and `economics` first — those are real,
tested, and immediately useful.

---

## How a future connector should be built

1. Confirm the target key is SHIPPED, not PLANNED.
2. Write a thin adapter: source system → this dict shape. No new
   precedence logic — the consumer already exists.
3. Test the adapter against the real precedence-level tests already in
   `tests/` (e.g. `tests/test_uaal_layer.py` for `enterprise_state`
   shape correctness) before connecting it to a live system.
4. Never populate a field with a synthetic/placeholder value in
   production — an absent field (which SKIPS the check) is always
   safer than a fabricated one (which could silently pass or fail a
   check incorrectly).
