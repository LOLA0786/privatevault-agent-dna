# 0006 — INDETERMINATE is a first-class outcome, not an error

Status:     accepted
Date:       2026-08-13
Commit:     be7bad4d922a34248bdf1356fd33fa6d1871901a
Pinned by:  tests/test_execution_feedback.py::test_indeterminate_is_not_ok_and_not_divergence

## What forced the decision
Two alternatives look cleaner on a dashboard. Treat "we wrote bytes
and then lost the response" as `error` — then an auditor infers the
world did not change, which may be false. Treat it as `ok` because
"we probably sent it" — then divergence detection and closure both
lie. Folding it into enforcement divergence ("executed a BLOCK")
is worse: an ALLOW that timed out after write is not a policy
violation.

The tempting product move is to infer success from a 200, or to
retry until the status is known. Inference is how `ok` gets minted
from hope.

## The decision
DRP execution status includes `indeterminate` as a peer of `ok`,
`error`, and `refused`. `ok` is never inferred. An INDETERMINATE
record is not divergence. Sidecar and gateway paths that begin
transport write and then lose completion record INDETERMINATE with
`tool_executed=None` and do not auto-retry. Optional `response_digest`
binds witnessed response bytes when they exist; it does not upgrade
the status.

## What this costs us
Operators and verifiers must handle a fourth state. Reports that
want a binary "did it run?" cannot be answered from the log after
a mid-write failure. Clients that mapped any non-ok to retry will
double-spend unless they honour 0005.

## What would make us revisit
A closure protocol that cryptographically distinguishes "peer
acknowledged the exact bytes" from "we wrote and heard nothing,"
verified independently of the producing runtime. Collapsing
INDETERMINATE into `error` to simplify a SIEM export is not a
trigger.
