# 0010 — PV_SECURE_PROFILE refuses PV_ALLOW_NO_AUTH rather than warning

Status:     accepted
Date:       2026-08-13
Commit:     b75e96bc5393777951fb53d3669d58284c13a64c
Pinned by:  tests/test_secure_profile.py::test_secure_profile_refuses_allow_no_auth

## What forced the decision
`PV_ALLOW_NO_AUTH=1` exists so a laptop can boot the API without
minting keys. Combining it with `PV_SECURE_PROFILE=1` and printing
an UNSAFE banner looks like "secure defaults with an escape hatch."
That is tempting because compose files, CI smoke tests, and the
container healthcheck all want a boot path, and because a warning
does not break anyone's script.

A warning is not a control. The next person exports both flags
from a platform profile "just to be sure," and production decides
as `authorization_mode=open`. F-05 was exactly this class of
caller- or operator-skippable enforcement.

## The decision
`PV_SECURE_PROFILE=1` and `PV_ALLOW_NO_AUTH=1` cannot both be set.
Composition raises at startup. The secure profile also demands API
keys, grants, receipt signer, trust roots, and the execution trust
bundle, and forces cross-agent `execution_id` and loop-events
required. Open authorizer remains an explicit development opt-in
when the secure profile is off, recorded in evidence, not a
request flag.

## What this costs us
The Docker smoke test still starts with `PV_ALLOW_NO_AUTH=1` and
therefore does not exercise the secure profile. Developers cannot
"try secure defaults" without real key material. Platform compose
must keep the two flags from drifting back together.

## What would make us revisit
A third named profile that is neither open nor secure (for
example shadow-only) with its own tests and a sealed posture
field. Treating a log line as sufficient when both flags are set
is not a trigger.
