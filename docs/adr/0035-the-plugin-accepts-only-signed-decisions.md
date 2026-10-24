# 0035: The plugin accepts only signed decisions

Status:     accepted
Date:       2026-10-24
Pinned by:  tests/test_signed_decisions.py::test_hook_refuses_a_forged_answer;
            tests/test_signed_decisions.py::test_hook_accepts_a_real_signed_allow;
            tests/test_signed_decisions.py::test_ed25519_agrees_with_libsodium

## What forced the decision
The hook trusted any answer from `PV_ENFORCE_URL` that said "allow". ADR 0033
refused plain http to other machines, but an https server, a proxy that can
read the traffic, or anything that can take over the port could still answer
"allow" for any call. The red team listed this as the last open gap.

## The decision
- `pv up` creates an Ed25519 signing key in `~/.privatevault/signing.key`
  (owner-only, once) and signs every decision with it. It publishes the
  public key as `~/.privatevault/decision-key.pub`. `--print-env` never
  prints the seed.
- `/v1/decide` returns the record's signature (`envelope`) with the record.
- When a key is pinned (`PV_DECISION_KEY`, or else
  `PV_HOME/decision-key.pub`), the hook accepts "allow" or "ask" only if all
  of these hold: the record hashes to its `record_hash`; the envelope is
  Ed25519 over that hash by the pinned key and verifies; the record names
  this agent, this capability, this call's `request_id` (Claude Code's
  `tool_use_id`, or a fresh random id) and the digest of these exact
  arguments; its decision is the one the answer gives; and it is no more
  than ten minutes from the hook's clock. Anything else is refused, with the
  reason. A refusal ("block") needs no signature.
- The hook verifies Ed25519 in the standard library (`hooks/pv_ed25519.py`,
  RFC 8032), checked against libsodium and the RFC test vectors, so it still
  runs on any python3.
- With no key pinned the hook behaves as before.

## What this costs us
- About 4 ms per tool call to verify.
- The local pin is trust on first use: the key file is created by `pv up`
  in a folder the agent cannot read or write (ADR 0033, 0034). For a server
  on another machine, the operator sets `PV_DECISION_KEY` to that server's
  public key; the local file then does not apply.
- Rotating the key means updating the pin: delete `signing.key` and restart
  `pv up` (it writes a new public key), or change `PV_DECISION_KEY`.
- A replayed record is refused because it names another call; the clock
  window bounds how long a captured answer for this exact call stays valid.

## What would make us revisit
Keys held in a KMS for team servers (the API already supports them,
ADR 0023) with the pin distributed by managed settings; signed refusals, if
an operator needs proof of every block as well.
