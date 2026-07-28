# Authority Provenance v0.1-experimental

This directory contains strict JSON Schemas for the trust bundle, signed
delegation grants, and three-verdict authority receipts.

The executable validation contract is agent_dna/authority_v01.py.

Strict protocol rules:

- Unknown fields and duplicate JSON keys are rejected.
- Floating-point values are forbidden.
- Money uses integer minor units and an ISO 4217 currency code.
- Only Ed25519 keys are supported.
- Canonicalization is RFC 8785.
- Actions match exactly and cannot contain wildcards.
- Resources may use only one trailing :* wildcard.
- Grant validity is a half-open interval.
- Verification uses decision_timestamp, not the verifier's current clock.
- A missing policy result is represented as JSON null.
- Under pv-fail-closed/0.1, null or unknown results compose to DENY.

Verify one receipt with tools/pv_authority_cli.py.

The authority CLI runs offline but imports `agent_dna.authority_v01`; it is
runtime-coupled and is not an independently implemented authority verifier.
The independently implemented ledger verifier is `tools/verify_records.py`.

Run a readiness assessment with:

pv authority scan --input actions.jsonl --trust-bundle trust-bundle.json
