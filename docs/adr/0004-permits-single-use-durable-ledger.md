# 0004 — Permits are single-use against a durable ledger

Status:     accepted
Date:       2026-08-09
Commit:     a43e05485f88c7cd6e1aeb652f120517595dfc23
Pinned by:  tests/test_consume_ledger.py::test_second_verify_refused_as_consumed;
            tests/test_authorize_mint_claim.py::test_sequential_mint_returns_byte_identical_authorization

## What forced the decision
In-process "already consumed" flags and caller-attested `already_consumed`
look like single-use and pass a unit test in one process. They do not
survive restart, and a second worker will happily verify the same
`execution_authorization_id`. That is tempting because SQLite and
`BEGIN IMMEDIATE` are operationally annoying, and because minting a
fresh UUID per call "feels" unique.

The audit finding (F-02 / PV-006 residual) was that uniqueness of id
is not uniqueness of effect: without a durable claim, "single-use" is
a wish.

## The decision
Successful `verify_execution_authorization(..., consume_ledger=...)`
atomically claims `execution_authorization_id` in SQLite (`BEGIN
IMMEDIATE` + UNIQUE). A second claim is `EXECUTION_AUTHORIZATION_CONSUMED`.
Caller `already_consumed` may only tighten, never relax. The claim
survives process restart. Library verify without a ledger remains
caller-attested for consumption and is not the production path.

`POST /v1/authorize` additionally claims `decision_id` in
`execution_authorization_mint` (`BEGIN IMMEDIATE` + UNIQUE). The first
valid mint stores one signed authorization. Identical authenticated
replay returns those stored bytes — it does not re-sign. See ADR 0016.

## What this costs us
A crash after consume and before or during send burns the permit
(see 0005). An INDETERMINATE, consumed, or expired mint claim is not
replaced automatically. Administrative remint recovery is deferred;
until a reviewed recovery authorization model exists, operators fail
closed. Omitting `consume_ledger` on a library caller silently returns
to attestation.

## What would make us revisit
An explicit recovery API for a burned unused id, with its own
authorization model and adversarial tests. Moving consumption to
Redis/"eventually consistent" without the same atomic exclusive claim
is not a trigger.
