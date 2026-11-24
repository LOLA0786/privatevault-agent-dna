# Onboarding

For an engineer joining PrivateVault, senior or intern. By the end of day one
you can run everything; by the end of the first week you can change the
trusted core safely.

## Day one: run it

Each command proves something; run them in this order.

```bash
uv sync --locked --extra dev
uv run python examples/composed_line_demo.py
uv run python tools/run_adversarial.py
uv run python -m demos.live_checkout.challenger --actions 20
uv run pytest -q
```

1. The locked toolchain, on the Python pinned in `.python-version`.
2. Every precedence level fires once; then a tampered log is caught by a
   verifier that does not import this code.
3. Sixteen attacks against the precedence ladder.
4. The continuous challenger: every approved refund is attacked on real
   services and judged by the payments ledger
   ([../demos/live_checkout/challenger.py](../demos/live_checkout/challenger.py)).
5. The suite. Set `TEST_DATABASE_URL` to a PostgreSQL 16 server to include
   the PostgreSQL tests, as CI does.

## Read, in this order

1. [../INVARIANTS.md](../INVARIANTS.md): what must never break, and the tests
   that hold each promise.
2. [../ARCHITECTURE.md](../ARCHITECTURE.md): one decision end to end, the
   precedence ladder, trust boundaries.
3. [architecture/README.md](architecture/README.md), then
   [architecture/FLOWS.md](architecture/FLOWS.md): every part that runs and
   every flow.
4. [WHAT-WE-DO-NOT-CLAIM.md](WHAT-WE-DO-NOT-CLAIM.md): the limits, stated
   plainly.
5. The decisions behind the money path, in [adr/README.md](adr/README.md):
   0019 (the receiver gate), 0020 (single-use approvals), 0026 (the evidence a
   permit cites), 0041 to 0043 (reservation, delegation budgets, daily
   limits), 0045 (facts from the system of record) and 0046 (a refused decide
   gives back its spend).

## The trusted core

The code where a mistake can move money or forge evidence:

| Area | Code |
|---|---|
| Decide, authorize, the seal | `api/server.py` |
| The ladder, breaker, grants and their spend | `agent_dna/decision.py`, `agent_dna/circuit_breaker.py`, `agent_dna/grants.py`, `agent_dna/grant_spend.py` |
| Records and signatures | `agent_dna/decision_record.py`, `agent_dna/decision_recorder.py`, `agent_dna/signer_bridge.py` |
| The exact-byte sidecar | `agent_dna/connector/adapters/exact_byte_http.py` |
| The receiver gate | `agent_dna/receiver/gate.py` |
| Independent verifiers | `tools/verify_records.py`, `tools/verify_receiver_receipts.py`, `tools/verify_lineage.py` |
| Wire contracts and vectors | `spec/` |

A change here needs an ADR when behaviour changes, a test that fails before
the change with a negative control beside it, a person who has read every
changed line, the gates in [../CONTRIBUTING.md](../CONTRIBUTING.md), and, on
the money path, a challenger run with no failing verdicts.

## Making a change

1. Find the ADR that covers the area; write a new one if behaviour changes.
2. Write the test first and watch it fail; add a negative control that shows
   the test can fail.
3. Make the change. Keep the pull request small enough for one person to read
   every line.
4. Run the gates in [../CONTRIBUTING.md](../CONTRIBUTING.md). They are the CI
   gates; `tests/test_contributing_gates.py` keeps the two lists equal.
5. Update `CHANGELOG.md`, the architecture pages the change touches, and
   [WHAT-WE-DO-NOT-CLAIM.md](WHAT-WE-DO-NOT-CLAIM.md) for anything you cannot
   prove. If imports changed, regenerate the maps with
   `python tools/archmap.py` and `python tools/depmap.py`.

## Working with AI assistants

We build PrivateVault with AI assistants, openly: an assistant can draft, a
person owns. The rules are in [../CONTRIBUTING.md](../CONTRIBUTING.md);
coding agents follow [../AGENTS.md](../AGENTS.md). The human brief that
commissioned the architecture map and the ADRs is kept in
[process/architecture-map-brief.md](process/architecture-map-brief.md).

## Glossary

| Term | Meaning |
|---|---|
| Decision | The answer to `POST /v1/decide`: allow (200), require approval (202) or block (403), sealed as a record |
| Precedence ladder | The eight ordered levels a decision passes through; the first that fires decides |
| Grant | A capability given to an agent, with expiry, revocation and a cumulative budget |
| Permit | Single-use, signed authority to send exact bytes, minted by `POST /v1/authorize` from a sealed allow |
| Sidecar | The agent-side dispatcher: it sends exactly the bytes a permit covers, or nothing |
| Receiver gate | Runs in front of the system of record; admits each permit once and signs a receipt for every request |
| Receipt | The receiver gate's signed record of what it admitted or refused |
| Record, envelope | A sealed, hash-chained decision and its signature |
| Checkpoint | A signed head of a chain, which lets a verifier prove nothing was cut from the end |
| Reservation | At most one live allow per business transaction (ADR 0041) |
| Fact source | The system of record the server reads decision facts from (ADR 0045) |
| Delegation chain | Authority passed from agent to agent; each link can only narrow it (ADR 0042) |
| DRP | The wire format of decision records, specified in `spec/` |
| Challenger | The continuous pen tester that attacks every approved action |
