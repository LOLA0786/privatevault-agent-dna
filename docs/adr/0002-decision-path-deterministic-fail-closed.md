# 0002 — The decision path is deterministic and fail-closed

Status:     accepted
Date:       2026-07-08
Commit:     ea99131c08a99b1ecd4d3d967df630f13fc35b89
Pinned by:  tests/test_fail_closed.py::test_raising_scorer_fails_closed

## What forced the decision
The alternative is fail-open with a warning: if the scorer, the
authorizer, OPA, or an invariant checker throws, let the action
through and log it. That is tempting in a demo and in any on-call
rotation that would rather not page on a buggy plugin. It is also
how enforcement dies — an attacker, or just a broken dependency,
turns the monitor into a no-op without changing a single ALLOW.

The other tempting alternative is "best-effort determinism": same
policy, same inputs, mostly the same verdict, except when a model
or a cache is involved. An auditor cannot replay "mostly."

## The decision
Identical inputs against a pinned policy version produce the same
verdict, with zero model inference on the decision path. Any internal
fault on that path — scorer, invariants, authorizer, UAAL, connector —
is a deterministic BLOCK (`engine_fault` / HTTP 403), never a pass
and never an unhandled crash. Non-drift precedence levels are
declared deterministic in the committed contract.

## What this costs us
A faulty plugin takes the agent down hard rather than silently
continuing. Operators must keep evidence sources and policy engines
available; "degrade to allow" is not a supported posture. Replayability
is a narrower claim than proof-theoretic soundness, and we do not
upgrade it in marketing.

## What would make us revisit
A named, operator-visible degraded mode that still cannot ALLOW a
sensitive capability class, with a distinct reason code, a sealed
record of the degradation, and an adversarial test that a fault
cannot widen grants. Softening `test_fail_closed.py` to make a flaky
integration pass is not a trigger.
