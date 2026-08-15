# 0008 — The dispatch witness is signed after send, never before

Status:     accepted
Date:       2026-08-13
Commit:     09dde9a71e2a7bfa45ec4ef15a4d64e73313a61d
Pinned by:  tests/connector/test_exact_byte_http.py::test_callback_sending_different_bytes_is_not_executed

## What forced the decision
Signing the witness before `write()` looks like it "binds intent"
and lets you stamp a record even if the process dies mid-send.
That is tempting because it always produces a signature, and
because tests can assert a witness without a real socket.

A pre-send signature attests that we meant to send. After a
substituted body, a partial write, or a failure, it attests a
lie: the bytes and peer in the witness are not what the sidecar
observed. Auditors will treat a signed witness as evidence the
bytes left. If we sign first, we have manufactured that evidence.

## The decision
The sidecar freezes the buffer, verifies, consumes, then writes.
`observed_at` is stamped after the body is written. The dispatch
witness is created and signed only in that after-send path, over
the bytes, TLS peer, and (with closure) HTTP status the sidecar
independently observed. If committed bytes differ from the frozen
buffer, the outcome is INDETERMINATE and there is no witness.

## What this costs us
A crash after write and before sign leaves INDETERMINATE with no
witness — we cannot prove what left, and we still burned the
permit. We do not claim the witness proves delivery, only local
observation of a completed send path.

## What would make us revisit
A hardware or out-of-process attest that can bind "these bytes
were written on this socket" without a process-local signer,
with a test that a pre-send signature cannot verify as a dispatch
witness. Signing speculatively to make a dashboard always show
a signature is not a trigger.
