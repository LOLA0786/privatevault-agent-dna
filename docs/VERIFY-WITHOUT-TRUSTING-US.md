# How to verify PrivateVault’s claims without trusting PrivateVault

**Audience:** bank / enterprise procurement, security architecture, third-party
risk.  
**Time:** under one hour with a laptop and this repository (or an evidence
bundle a pilot exports).  
**Scope:** verify integrity and fail-closed behaviour of the decision /
authorization path. This page does **not** claim SOC 2, complete mediation of
side channels, or that a compromised signer at signing time is detectable after
the fact.

---

## What you can check yourself

| Claim | How you verify | What a pass means |
|-------|----------------|-------------------|
| Decisions are hash-chained and tamper-evident | Export audit JSONL → run the **stdlib** verifier | Chain is intact; the producing runtime was **not** imported |
| Signatures (when used) bind to keys **you** pin | Verifier `--envelopes` + `--trusted-key` | Envelope matches a key you supplied, not a key we embedded |
| Mint requires a sealed ALLOW | Call `/v1/authorize` without `decision_id` / with a BLOCK | Distinct refuse codes; no permit |
| One ALLOW → at most one mint | Authorize twice on the same `decision_id` | Second call: `AUTHORIZE_DECISION_ALREADY_MINTED` |
| Single-use permit | Verify the same EA id twice with the durable ledger | Second: `EXECUTION_AUTHORIZATION_CONSUMED` |
| Wire binding | Alter outbound bytes after mint; verify | Digest mismatch; permit not consumed |
| Inventory of agent tool use | `pvscan` on Claude Code / session logs | Local read-only report; nothing leaves the machine |
| CI / suite honesty | `python tools/prove.py -o proof.json` | Sealed proof-of-run with `report_hash` |

---

## Minimum reproduction (no PrivateVault account)

```bash
git clone https://github.com/LOLA0786/privatevault-agent-dna
cd privatevault-agent-dna
pip install -e ".[dev]"   # or: uv sync

# 1) Full suite + adversarial corpus + independent verifiers
python tools/prove.py -o /tmp/proof-of-run.json
# Keep report_hash from the output. Re-run later; hash changes only if inputs change.

# 2) Stdlib chain verifier (does not import agent_dna runtime)
python tools/verify_records.py spec/test-vectors/clean.jsonl

# 3) Agent inventory (read-only; optional)
python tools/pvscan.py benchmarks/live-agent/claude_session_2026-08-01.jsonl \
  --json /tmp/pvscan.json
```

Trusted signature mode (optional; requires PyNaCl and keys **you** pin):

```bash
python tools/verify_records.py <audit.jsonl> \
  --envelopes <envelopes.jsonl> \
  --trusted-key <auditor-held-public-key>
```

---

## What to ask for in an RFP / pilot handoff

1. **Proof-of-run file** (`pv-proof-of-run/1`) with `report_hash`.  
2. **Audit export** (canonical JSONL) + optional envelopes for the pilot window.  
3. **Pinned public keys** for receipt / execution signers (your custody, not ours).  
4. **Sample refuse transcripts** for: missing decision reference, BLOCK decision,
   org unbound/mismatch, second mint, second consume, wire tamper.  
5. Explicit **non-claims** page from the same commit: `docs/WHAT-WE-DO-NOT-CLAIM.md`.

If any of (1)–(4) cannot be produced from the deployment under review, treat the
deployment as non-compliant with this verification kit.

---

## Precise language (so legal / risk do not over-read)

**Say:** an outsider can verify the audit trail and refuse paths **without
trusting our later handling of the evidence**, and without importing the
producing runtime.

**Do not say:** “without trusting us” in the absolute. A compromised signer at
**signing time** can produce a schema-valid signature; independent verification
detects post-hoc tampering and unknown keys, not a traitor in the signing
ceremony. Pin keys outside the producer. Rotate on compromise.

**Also do not claim from this kit alone:** that every real-world side effect
passed through PrivateVault (complete mediation), model accuracy, or
certification status.

---

## Mapping to common control questions

| Control question | Evidence artifact |
|------------------|-------------------|
| Who decided, and why? | DecisionRecord: `decision`, `triggered_by`, `reason`, `record_hash` |
| Was execution authorized for these bytes? | Execution authorization + dispatch verify report |
| Was the permit reused? | Consume ledger / `EXECUTION_AUTHORIZATION_CONSUMED` |
| Can we re-check without the vendor online? | `tools/verify_records.py` (stdlib chain mode) |
| What did the coding agent attempt? | `pvscan` inventory (`pv-scan-inventory/0.1`) |

---

## Contact for design-partner verification support

Use the repository issues or the pilot channel named in your engagement letter.
This document is versioned with the code; cite the **git commit** and
**report_hash** together.
