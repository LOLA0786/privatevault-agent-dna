# 0016 — One live stored permit per decision

Status:     accepted
Date:       2026-08-20
Pinned by:  tests/test_authorize_mint_claim.py::test_sequential_mint_returns_byte_identical_authorization

## What forced the decision
Binding `/v1/authorize` to a sealed ALLOW still left mint itself
non-idempotent: each call generated a new `execution_authorization_id`,
nonce, and signature. Two processes, two retries, or a client replay
produced two live permits for one decision. That is tempting because
HTTP retries are normal and because "new UUID per call" looks unique.

Uniqueness of permit id is not uniqueness of effect. Without a durable
mint claim, one ALLOW is not one live authorization.

## The decision
The first valid `/v1/authorize` call atomically creates and stores one
signed execution authorization. The claim key is `decision_id` in
SQLite table `execution_authorization_mint` (`UNIQUE` +
`BEGIN IMMEDIATE`). Concurrent writers and a second process using the
same database converge on one stored permit. Database/process restart
preserves the claim.

An identical authenticated request for the same decision and identical
bindings returns the stored authorization:

- same `execution_authorization_id`;
- same nonce;
- same signature;
- byte-identical serialized authorization.

Replay does not re-sign or generate new authorization bytes.

A request with changed action, arguments, wire digest, destination,
audience, peer, tenant, agent, or authenticated principal hard-refuses
with `AUTHORIZE_PERMIT_BINDING_CONFLICT`.

A consumed permit is not replaced (`AUTHORIZE_PERMIT_ALREADY_CONSUMED`).
An expired permit is not replaced automatically (`AUTHORIZE_PERMIT_EXPIRED`).
An INDETERMINATE outcome does not unlock another mint
(`AUTHORIZE_PERMIT_INDETERMINATE`).

The uniqueness constraint and transaction are the authority. An
in-process lock is not sufficient.

## What this costs us
Administrative remint recovery is deferred. There is no recovery
endpoint in this change. A burned, expired, or indeterminate mint
claim stays fail-closed until its authorization model is separately
designed and reviewed. Operators cannot unstick a spent decision_id
from this API.

## What would make us revisit
A reviewed recovery authorization model with its own tests
(multi-process, restart, concurrent recover, refuse-without-privilege).
Replacing SQLite UNIQUE with an in-process mutex, Redis SET without
compare-and-set, or "just remint after expiry" is not a trigger.
