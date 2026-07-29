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

## Scan an observed Claude Code session

After installing the package, scan one Claude Code JSONL transcript:

~~~bash
pv-coding-eval scan \
  --claude-jsonl /path/to/session.jsonl \
  --output observed-events.jsonl
~~~

The scanner emits the strict `pv-coding-observed-event/0.1` JSONL contract.
Compound Bash requests can produce multiple ordered capability events.

Privacy and failure behavior:

- Raw prompts, tool arguments, file contents, session IDs and tool-use IDs are not written.
- Inputs, source paths and source files use SHA-256 digests.
- Session, agent and event identifiers are pseudonymous.
- Activity evidence is marked `OBSERVED`; authority is not inferred.
- Malformed, mixed-session, duplicate, mutated and empty inputs fail closed.
- Output replacement is atomic and completed files use `0600` permissions.

The adapter supports Claude Code assistant-message `tool_use` JSONL only. It
does not claim support for unrelated transcript formats.
