# 0025: A capability covers only the operations the operator declared

Status:     accepted
Date:       2026-10-19
Pinned by:  tests/test_operation_registry.py::test_undeclared_request_is_a_sealed_block;
            tests/test_operation_registry.py::test_read_grant_cannot_obtain_a_transfer_permit;
            tests/test_operation_registry.py::test_mint_checks_the_credential_audience;
            tests/test_operation_registry.py::test_secure_profile_refuses_to_mint_without_a_registry;
            tests/test_operation_registry.py::test_blocked_request_spends_no_budget

## What forced the decision
An external review (19 October 2026, finding 1) gave an agent one grant,
`crm.read_contact`, under the secure profile. The agent asked to read a
contact while sending `POST /api/v1/transfers` with payment parameters to a
payment service. `/v1/decide` allowed it, `/v1/authorize` minted a permit,
and the receiver admitted the transfer. Each component was consistent with
the others: the API checked the caller's labels against each other, the
grant registry looked up agent plus capability, and the receiver checked the
operation it had been signed. Nothing said what `crm.read_contact` means.

## The decision
The operator declares, in `PV_OPERATIONS_FILE` (`pv-operations/0.1`,
`agent_dna/operation_registry.py`), each operation a capability covers:
transport, destination, `METHOD path`, credential audience (default: the
destination), execution action name (default: the capability), resource
(a prefix or an exact list), wire content type if fixed, and a required JSON
Schema for the parameters.

- **At decide**, a bound request whose capability declares no matching
  operation is a sealed BLOCK (`triggered_by: operation_registry`), decided
  before the precedence ladder: it spends no grant budget, consumes no
  approval and moves no breaker, and the attempt is on the record.
- **At mint**, the request is checked again against the registry as it is
  now, including the credential audience, which the decide-time context does
  not carry. A mismatch refuses (`AUTHORIZE_OPERATION_MISMATCH`,
  `AUTHORIZE_OPERATION_NOT_DECLARED`). The response names the operation id
  and the registry digest the permit was checked against.
- **Under `PV_SECURE_PROFILE`**, a mint without a registry is refused
  (`AUTHORIZE_OPERATIONS_REQUIRED`). `tools/init_secure_profile.py` writes an
  empty `operations.json`, so a new deployment mints nothing until the
  operator declares its operations.
- A malformed file stops start-up. `GET /v1/runtime` reports the registry
  and its digest.

Without the secure profile and without a file, behaviour is unchanged and
`/v1/runtime` says the binding is not configured.

## What this costs us
- Every mintable operation must be declared before it works under the
  secure profile; integrators write one entry per route.
- Routes are exact strings. A route with an id in the path
  (`/v1/invoices/123/pay`) needs the id in the parameters or one entry per
  route; there are no path templates yet.
- The registry digest is in the mint response, not inside the signed permit:
  adding a field to the permit is a spec change. The permit's own
  destination, operation and audience are what the registry checked.
- The registry is configuration the operator owns. A wrong entry authorizes
  what it says; the review of that file is the control.

## What would make us revisit
Path templates, a registry served and signed separately from the API, or
receivers that check the registry digest themselves (permit spec 0.3).
