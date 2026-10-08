# 0019 — The system of record verifies the permit (receiver gate)

Status:     accepted
Date:       2026-10-08
Pinned by:  tests/receiver/test_receiver_gate.py::test_direct_call_without_permit_is_refused;
            tests/receiver/test_receiver_http.py::test_proxy_blocks_bypass_and_forwards_permitted_call_once;
            tests/receiver/test_receiver_independent_verifier.py::test_cli_verifies_real_ledger_in_isolation

## What forced the decision
Every permit check we ship runs on the agent's side of the wire. The
exact-byte sidecar verifies, consumes, and witnesses before it sends, and
its own docstring says it is not complete mediation unless the network
denies the agent every other path. A buyer comparing agent-security
vendors asks one question first: *what stops the agent calling the
payment API directly and skipping you?* Before this ADR the honest answer
was "network policy you have to build", which is the same answer an
in-agent sidecar vendor gives.

The tempting fix is to make the agent-side sidecar harder to bypass.
That keeps the wall inside the environment the agent controls. The
party that actually loses money on a bad transfer is the system of
record, and it is the only party that sees every request that reaches
it, whatever path the request took.

## The decision
The permit travels with the request (`X-PV-Execution-Authorization`,
unpadded base64url of the RFC 8785 canonical permit, one encoding only).
A `ReceiverGate`, operated by the owner of the system of record, admits a
request only when that request carries a permit that:

1. is signed by an `execution_authorization_signer` key in a trust bundle
   the operator pinned, and names that bundle's digest;
2. names this receiver as `credential_audience` and one of its
   destinations (a permit for another system is refused);
3. binds the exact received `METHOD path` (query string included);
4. is inside `not_before`/`expires_at` (skew bounded to 30s, default 0);
5. binds the SHA-256 and length of the received body;
6. whose `action.parameters`, under the named serialization, *are* the
   received body (payee and amount the agent signed for are the bytes
   that arrived);
7. passes operator-owned local checks, which may only refuse;
8. has not been admitted by this receiver before (receiver-owned durable
   ledger, `BEGIN IMMEDIATE` + primary key).

Every evaluated request, admitted or refused, appends one receipt signed
by the receiver operator's key and hash-chained to the previous one.
The gate refuses to start if that key appears in the PrivateVault trust
bundle (same independence rule as ADR 0009). `tools/verify_receiver_receipts.py`
verifies the chain without importing `agent_dna`.

Deployment shapes: `ReceiverGateMiddleware` (ASGI, for systems the
operator writes) and `ReceiverGateProxy` (reverse proxy in front of a
system the operator cannot modify). The exact-byte sidecar attaches the
header when `attach_permit_header=True`; the header never changes the
bound body bytes.

## What this costs us
- Only operations routed through a gate are protected. Coverage of a
  bank's APIs, and making the gate the sole network path to them, are
  deployment properties this code cannot prove.
- A refused request does not burn its permit; an admitted request whose
  upstream call then fails has burned it (ADR 0005 applies at the
  receiver too). The proxy reports that as `INDETERMINATE`.
- The receipt chain is per SQLite file. Multi-host receivers need a store
  with the same exclusive-claim guarantee; not provided.
- Refusal receipts are written for unauthenticated traffic. A flood of
  permit-less requests grows the ledger; rate limiting is the operator's.
- Only `pv-json-parameters/0.1` bodies are bindable at the receiver.
  Form-encoded, multipart, compressed, or framed bodies are refused, not
  normalized.
- Receipts prove what the gate admitted, not what the upstream did with
  it. Reconciliation against the system's own ledger is separate.

## What would make us revisit
A receiver that needs a body format other than the named serializer
(add a serializer and its own ADR, never a normalizer). A request to let
an unprotected route accept writes (refused by construction today;
only GET/HEAD may be unprotected). Any proposal to verify the permit with
a key the agent-side runtime also holds.
