# Putting the gate in front of a payment gateway's order API

Three ways to integrate the receiver gate (ADR 0019) with an order-create
API such as `POST /v1/orders`. All three verify the same thing, in the same
order, with the same refusal codes: the permit's signature against a pinned
trust bundle, its organisation, audience, destination and operation, its
validity window, the exact request bytes against the digest and length the
permit was minted for, the action the bytes encode, and single use through
the gate's own ledger. What differs is where that code runs and who owns
the ledger.

The demo (`run.py`) uses option A. The agent side (decide, approval,
permit, sidecar) is the same in every option and is not the gateway's
concern: the gateway only ever sees a permit header and bytes.

| | A. Reverse proxy | B. Middleware / SDK | C. Verify endpoint |
|---|---|---|---|
| Where the check runs | A separate process in front of the order API | Inside the gateway's request pipeline | A PrivateVault-run service the gateway calls |
| Gateway code change | None | One middleware registration (Python) or a port (other languages) | One outbound call before order creation |
| Who holds the ledger and receipt key | The gateway operator, in the proxy | The gateway operator, in process | PrivateVault (or a gateway-hosted instance of the service) |
| Single use guarantee | Atomic: the proxy consumes then forwards once | Atomic: consume then handle, in process | Consume at verify time; the gateway must create the order exactly once afterwards |
| Latency added | One extra hop on loopback or the same pod | Microseconds | One network round trip |
| Effort to a working pilot | 1 to 2 days | Python: 1 to 2 days. Java, Go, Node: 3 to 5 weeks for a conformant port | 1 week service side, 2 to 3 days gateway side |
| Effort to production | 1 to 2 weeks (TLS, HA ledger, key custody, monitoring) | 2 to 3 weeks on top of the port (ledger durability, key custody, release process) | 2 to 3 weeks (HA service, mTLS, ledger durability, SLOs) |
| Status today | Shipped: `agent_dna.receiver.asgi.ReceiverGateProxy`, containerised in `network/receiver_kit/` | Shipped for ASGI: `agent_dna.receiver.asgi.ReceiverGateMiddleware`. No other-language SDK exists | Not built. `ReceiverGate.check` is the function; the HTTP surface around it is new work |

## A. Gate as a reverse proxy in front of the order API

```
agent sidecar --https--> [receiver gate proxy] --http(s)--> order API (unchanged)
                               |
                          ledger + receipt key (gateway-owned)
```

The gate terminates the request, evaluates it, and either answers with a
refusal (403, 409 and the reason code, plus a signed receipt) or forwards
the exact bytes once with the permit header stripped and the receipt
digest added to the response (`X-PV-Receiver-Receipt`,
`X-PV-Receiver-Sequence`). The order API never sees an unpermitted request
and does not change.

What exists: `ReceiverGateProxy` (`agent_dna/receiver/asgi.py`), the
container and environment-driven configuration in
`network/receiver_kit/` (`config.py`: receiver id, destinations, pinned
issuer keys, receipt key file, upstream, ledger path; the process refuses
to start if any is missing), and the 15-minute `QUICKSTART.md` that runs
it with Docker Compose.

Work for a pilot: run the container next to the order API, pin the
PrivateVault issuer key, generate the receipt key, route the agent-facing
hostname to the proxy. Nothing in the order API changes.

Work for production: TLS termination at the proxy (or behind the
gateway's existing edge), a durable ledger (the SQLite ledger is
single-node; the ledger must survive restarts and must not be shared
without a lock, or the single-use guarantee is lost), custody and
rotation of the receipt key, health and refusal-rate metrics, and the
network rule that makes the proxy the only path to the order API. If the
upstream call fails after the permit is consumed, the proxy answers 502
with `upstream: INDETERMINATE`; the permit is spent and nothing is
retried. That is the intended fail-closed behaviour and the gateway's
reconciliation process should know about it.

Best when: the gateway is a black box, or a quick pilot is the goal.

## B. SDK or middleware inside the gateway

```
agent sidecar --https--> [gateway: TLS, auth, ReceiverGateMiddleware, handler]
                                               |
                                      ledger + receipt key (in process)
```

The same evaluation, as a middleware the gateway's own request pipeline
runs before the order handler. Refusals never reach the handler; admitted
requests reach it exactly once with the permit header removed. The
gateway keeps its own TLS, authentication, rate limiting and logging;
the gate adds its check and its receipts.

What exists: `ReceiverGateMiddleware` (`agent_dna/receiver/asgi.py`),
pinned by `tests/receiver/test_receiver_http.py`. It wraps any ASGI app,
so a Python gateway (FastAPI, Starlette) integrates in a few lines:

```python
from agent_dna.receiver.asgi import ReceiverGateMiddleware
from agent_dna.receiver.gate import ReceiverGate
from agent_dna.receiver.ledger import ReceiverLedger

gate = ReceiverGate(
    receiver_id="checkout.gateway.example",
    destinations=frozenset({"https://checkout.gateway.example"}),
    trust_bundle=pinned_bundle,  # PrivateVault issuer keys, pinned
    ledger=ReceiverLedger("/var/lib/pv/receiver.db"),
    receipt_signing_key=receipt_key,  # the gateway's own Ed25519 key
    receipt_key_id="gateway-receiver-01",
)
app = ReceiverGateMiddleware(order_api_app, gate)
```

Work for a pilot in Python: the lines above, plus key custody and a
ledger path. One to two days.

Work for other languages: a port of `agent_dna/receiver/gate.py` (about
550 lines: header parsing, schema check, Ed25519 verification against a
pinned bundle, RFC 8785 canonical JSON, SHA-256 of the body, the ordered
refusal list, the receipt chain). The spec vectors under `spec/` and the
Rust signer parity tests (`tests/test_rust_signer_parity.py`) are the
conformance target. Three to five weeks for a careful port with its own
test suite, plus two to three weeks of hardening. PrivateVault would want
to review a port against the vectors before it is called a receiver.

Best when: the gateway is Python, or the gateway team wants the check in
their own release process and their own observability, with no extra
hop.

## C. Gateway calls a verify endpoint

```
agent sidecar --https--> [gateway] --POST /v1/receiver/verify--> [verify service]
                             |                                        |
                     creates the order once                 ledger + receipt key
                     only on "admitted"
```

The gateway receives the request as it does today, then calls a verify
service with the method, path, headers and the exact body bytes (or the
body's SHA-256 and length; the bytes are safer because the service then
recomputes everything itself). The service runs the same evaluation,
consumes the permit in its ledger, signs a receipt, and answers
`admitted` with the receipt digest or a refusal with the reason code. The
gateway creates the order only on `admitted`, and must do so exactly
once: the permit is already spent, so a gateway-side failure after a
positive verify is the same INDETERMINATE case as the proxy's 502, and
must not be retried under the same permit.

What exists: `ReceiverGate.check(method, path, headers, body)` is the
whole evaluation and never raises. The HTTP service around it, its
authentication (the gateway must be the only caller, mTLS or a
gateway-held key), its ledger, and its operational surface are new work.
About one week to build and test the service; two to three days on the
gateway side for the outbound call and the exactly-once handling.

Trade-offs: the gateway must pass the bytes faithfully (the body as
received, before any parsing or re-serialisation), the verify call adds a
network round trip, and the ledger lives with whoever runs the service.
If PrivateVault runs it, the gateway gains nothing to operate but depends
on the service's availability: an unreachable verify service means no
orders from agents, which is fail-closed and must be an agreed outcome.

Best when: the gateway is not Python, a port is not wanted, and the
gateway team prefers one outbound call to a new component in their path.

## What is the same in all three

- The refusal codes and the receipt format. `tools/verify_receiver_receipts.py`
  verifies receipts from any of the three with the receiver's public key.
- The agent side. PrivateVault decides, the approver signs, a permit is
  minted for the exact bytes, the sidecar sends them. The gateway never
  learns the agent's credentials and never evaluates policy.
- The limits. The gate verifies that these bytes were permitted; it does
  not verify that the merchant exists, that the buyer has funds, or
  anything else the gateway already checks. Those checks stay where they
  are, after the gate.
