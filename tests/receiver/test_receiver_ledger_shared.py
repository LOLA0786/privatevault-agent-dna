"""The receiver ledger on PostgreSQL: the same claims, shared by every host (ADR 0049).

Each receiver host keeps its own ReceiverLedger; with a PostgreSQL URL they
all point at one database. These tests hold that ledger to the SQLite one
operation for operation, then race two instances with separate connection
pools, as two hosts have, on one permit, one decision, one approval and one
business key. Each is admitted exactly once, and the receipts stay a single
unforked chain.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from agent_dna.authority_v01 import sha256_digest
from agent_dna.receiver.ledger import (
    CLAIM_DUPLICATE_APPROVAL,
    CLAIM_DUPLICATE_DECISION,
    CLAIM_DUPLICATE_TRANSACTION,
    ReceiverLedger,
)
from agent_dna.receiver.receipts import GENESIS_DIGEST
from agent_dna.receiver.transactions import EXECUTED, INDETERMINATE, NOT_EXECUTED
from tests.pg_support import requires_pg

ORG = "org-shared"
AT = "2026-11-26T10:00:00Z"


def _receipt(claimed: Any, sequence: int, previous: str) -> dict[str, Any]:
    return {
        "sequence": sequence,
        "previous_receipt_digest": previous,
        "claimed": claimed,
    }


def _verified_chain(ledger: ReceiverLedger) -> list[dict[str, Any]]:
    receipts = list(ledger.iter_receipts())
    previous = GENESIS_DIGEST
    for number, receipt in enumerate(receipts, start=1):
        assert receipt["sequence"] == number, "the receipt sequence has a gap or a fork"
        assert receipt["previous_receipt_digest"] == previous, (
            "the receipt chain is forked"
        )
        previous = sha256_digest(receipt)
    return receipts


@pytest.fixture
def hosts(dsn) -> Iterator[list[ReceiverLedger]]:
    ledgers = [ReceiverLedger(dsn), ReceiverLedger(dsn)]
    try:
        yield ledgers
    finally:
        for ledger in ledgers:
            ledger.close()


def _script(ledger: ReceiverLedger) -> list[Any]:
    def record(**kwargs: Any) -> Any:
        return ledger.record(make_receipt=_receipt, **kwargs)[0]

    return [
        record(
            claim=(ORG, "ea-1", AT),
            transaction=("refund", "ORD-1"),
            sources=[("decision", "d1"), ("approval", "a1")],
        ),
        record(claim=(ORG, "ea-1", AT)),
        record(claim=(ORG, "ea-2", AT), sources=[("decision", "d1")]),
        record(claim=(ORG, "ea-3", AT), sources=[("approval", "a1")]),
        record(claim=(ORG, "ea-4", AT), transaction=("refund", "ORD-1")),
        record(claim=None),
        ledger.record_outcome(ORG, "ea-1", 502, at=AT),
        ledger.resolve_transaction(
            ORG,
            "refund",
            "ORD-1",
            resolution=NOT_EXECUTED,
            actor="ops",
            note="the bank confirmed no payment",
            at=AT,
        ),
        record(claim=(ORG, "ea-5", AT), transaction=("refund", "ORD-1")),
        ledger.record_outcome(ORG, "ea-5", 200, at=AT),
        ledger.is_consumed(ORG, "ea-1"),
        ledger.is_consumed(ORG, "ea-9"),
        ledger.source_holder(ORG, "decision", "d1"),
        ledger.transactions(),
        ledger.transactions(open_only=True),
        ledger.transaction_events(ORG, "refund", "ORD-1"),
        list(ledger.iter_receipts()),
    ]


@requires_pg
def test_postgresql_ledger_matches_sqlite_operation_for_operation(dsn, tmp_path):
    sqlite = ReceiverLedger(tmp_path / "receiver.db")
    shared = ReceiverLedger(dsn)
    try:
        expected = _script(sqlite)
        assert expected[:6] == [
            True,
            False,
            CLAIM_DUPLICATE_DECISION,
            CLAIM_DUPLICATE_APPROVAL,
            CLAIM_DUPLICATE_TRANSACTION,
            None,
        ]
        # A 502 leaves the claim INDETERMINATE; resolving it returns the state it
        # resolved; the freed key is claimed again and that payment executes.
        assert expected[6:10] == [INDETERMINATE, INDETERMINATE, True, EXECUTED]
        assert _script(shared) == expected
        assert (
            len(_verified_chain(shared)) == 7
        )  # one receipt per record(); outcomes and resolutions add none
    finally:
        shared.close()


@requires_pg
def test_two_hosts_admit_one_permit_exactly_once(hosts):
    attempts = 16
    start = threading.Barrier(attempts)

    def attempt(number: int) -> Any:
        start.wait()
        return hosts[number % 2].record(
            claim=(ORG, "ea-race", AT), make_receipt=_receipt
        )[0]

    with ThreadPoolExecutor(attempts) as pool:
        results = list(pool.map(attempt, range(attempts)))

    assert results.count(True) == 1 and results.count(False) == attempts - 1
    assert hosts[0].is_consumed(ORG, "ea-race") and hosts[1].is_consumed(ORG, "ea-race")
    assert len(_verified_chain(hosts[1])) == attempts


@pytest.mark.parametrize(
    ("claim", "refusal"),
    [
        ({"sources": [("decision", "decision-9")]}, CLAIM_DUPLICATE_DECISION),
        ({"sources": [("approval", "approval-9")]}, CLAIM_DUPLICATE_APPROVAL),
        ({"transaction": ("refund", "ORD-9")}, CLAIM_DUPLICATE_TRANSACTION),
    ],
    ids=["decision", "approval", "business-key"],
)
@requires_pg
def test_two_hosts_admit_one_permit_per_decision_approval_and_business_key(
    hosts, claim, refusal
):
    attempts = 8
    start = threading.Barrier(attempts)

    def attempt(number: int) -> Any:
        start.wait()
        return hosts[number % 2].record(
            claim=(ORG, f"ea-{number}", AT), make_receipt=_receipt, **claim
        )[0]

    with ThreadPoolExecutor(attempts) as pool:
        results = list(pool.map(attempt, range(attempts)))

    assert results.count(True) == 1, results
    assert results.count(refusal) == attempts - 1, results
    assert len(_verified_chain(hosts[0])) == attempts


@requires_pg
def test_a_failed_receipt_leaves_no_claim_behind(dsn):
    ledger = ReceiverLedger(dsn)
    try:

        def signer_down(claimed: Any, sequence: int, previous: str) -> dict[str, Any]:
            raise RuntimeError("receipt signer unavailable")

        with pytest.raises(RuntimeError):
            ledger.record(
                claim=(ORG, "ea-x", AT),
                make_receipt=signer_down,
                transaction=("refund", "ORD-x"),
                sources=[("decision", "dx")],
            )

        assert not ledger.is_consumed(ORG, "ea-x")
        assert ledger.source_holder(ORG, "decision", "dx") is None
        assert ledger.transactions() == []
        assert list(ledger.iter_receipts()) == []
        claimed, receipt = ledger.record(claim=(ORG, "ea-x", AT), make_receipt=_receipt)
        assert claimed is True and receipt["sequence"] == 1
    finally:
        ledger.close()


@requires_pg
def test_a_database_ledger_says_it_is_shared_and_keeps_its_url_private(dsn, tmp_path):
    shared = ReceiverLedger(dsn)
    try:
        assert shared.shared and shared.path == "postgresql"
    finally:
        shared.close()
    assert ReceiverLedger(tmp_path / "receiver.db").shared is False
