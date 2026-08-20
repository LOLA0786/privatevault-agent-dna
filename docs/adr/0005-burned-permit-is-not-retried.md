# 0005 — A permit burned by transport failure is not retried

Status:     accepted
Date:       2026-08-13
Commit:     09dde9a71e2a7bfa45ec4ef15a4d64e73313a61d
Pinned by:  tests/connector/test_exact_byte_http.py::test_transport_write_then_raise_is_indeterminate

## What forced the decision
The obvious recovery is: consume failed or the socket died, so retry
the same permit, or auto-remint from the same ALLOW. That is tempting
because payment APIs teach "retry with idempotency key" and because
on-call would rather not explain a stuck spend to a customer.

Consume-then-send without a crash state is how you get a double
effect: the first attempt may have reached the peer; the second
will. Consume-after-success-only is how you get unbounded retries
of a permit that already moved money. Neither is acceptable.
Reminting the same `decision_id` after INDETERMINATE is the same
class of mistake: the first send may have taken effect.

## The decision
Once the sidecar has invoked transport write, the permit is already
claimed and the outcome is not retryable (`retryable=False`). A
timeout, reset, or substituted body after write has begun is
INDETERMINATE, not a signal to present the same id again. Recovery
is a new decision — never auto-retry the burned permit, and never
remint from the same `decision_id`. Administrative remint recovery
is deferred (ADR 0016). Handshake failure before write does not
consume.

## What this costs us
Operators eat a burned permit on every ambiguous send. Throughput
under flaky networks requires more ALLOWs, not a retry loop.
Idempotency keys in the dispatch record are a digest binding, not
a license to replay the permit.

## What would make us revisit
A durable dispatch state machine (RESERVED → DISPATCHING →
SUCCEEDED / FAILED_SAFE / INDETERMINATE) with a peer-visible
idempotency story that an offline verifier can check, plus a test
that a retried INDETERMINATE cannot produce a second write. HTTP
429 from the peer is not a trigger to set `retryable=True` on a
consumed id.
