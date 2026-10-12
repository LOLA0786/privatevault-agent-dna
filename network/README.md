# PrivateVault network kit

Everything a partner needs to run one side of the permit network, without
touching the core package. `network/` imports from `agent_dna/` and is not
part of the wheel.

North star: one independently operated receiver (the partner's infrastructure,
the partner's key) verifies a PrivateVault permit, refuses an altered action,
and produces receipts that pass the open verifier.

| Directory | Phase | What it is |
|---|---|---|
| `receiver_kit/` | 1 | Receiver gate as a reverse proxy in front of a dummy payment upstream, partner-owned receipt key, a test sender, and a one-page quickstart. |
| `registry/` | 2 | Signed JSON trust registry: issuers, active keys, revoked keys. Not built yet. |
| `issuer/` | 3 | Ten-line issuer example and LangGraph wiring. Not built yet. |
| `telemetry/` | 4 | Anonymised refusal records, local export only. Not built yet. |

Start with `receiver_kit/QUICKSTART.md`.
