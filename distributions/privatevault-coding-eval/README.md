# PrivateVault Coding Agent Evaluation v0.1

This package is a thin evaluation harness over the real
privatevault-agent-dna v0.3.0 runtime.

It does not contain a replacement policy engine, grant engine, signer, decision
engine, evidence engine, consensus implementation or ledger implementation.

The evaluator imports and exercises the actual PrivateVault components:

- AgentAction
- DecisionEngine
- GrantRegistry
- PolicyChecker
- invariant checks
- consensus checks
- EvidenceEngine
- DecisionRecord
- ReceiptSigner
- trusted-envelope verification

The evaluation kit also carries the actual standalone ledger verifier,
tools/verify_records.py.

The harness supplies coding-agent scenarios, invokes the real runtime, records
the actual results and prepares evidence for external review.

It is an evaluation harness, not an independently implemented verifier and not
a separate authorization runtime.
