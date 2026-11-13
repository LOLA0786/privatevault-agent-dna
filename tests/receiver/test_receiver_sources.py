"""A decision, and an approval, executes at most once at the receiver
(ADR 0039).

The agent side mints at most one permit per decision (ADR 0016) and uses an
approval once (ADR 0020). Someone who can write the agent-side database can
delete the rows that enforce both, or restore an older copy, and mint a
second permit. The receiver now claims the decision and the approval each
permit was minted from, in its own ledger, and refuses a second, different
permit for either, with or without a business transaction key.

Claims -> tests:
  - A second permit for an admitted decision is refused (409, signed
    receipt) and not consumed -> test_second_permit_for_the_same_decision_*
  - A permit for a new decision made under an admitted approval is refused
    -> test_second_permit_under_the_same_approval_is_refused
  - Permits with no approval collide only on their decision
    -> test_permits_without_an_approval_are_judged_by_decision_alone
  - Replaying the same permit is still "already consumed"
    -> test_replaying_one_permit_is_still_permit_consumed
  - Holds for an operation with no business key, and when the key differs
    -> test_*_without_a_business_key, test_a_different_invoice_*
  - Concurrent permits for one decision through two gates: one admitted
    -> test_concurrent_permits_for_one_decision_admit_one
  - A ledger created before this change gains the table on open
    -> test_an_existing_ledger_is_upgraded_on_open
"""

from __future__ import annotations

import sqlite3
import threading

from agent_dna.authority_v01 import sha256_digest
from agent_dna.receiver import gate as g
from agent_dna.receiver.gate import ReceiverGate
from agent_dna.receiver.ledger import ReceiverLedger
from agent_dna.receiver.permit_header import PERMIT_HEADER, encode_permit_header
from agent_dna.receiver.receipts import verify_receiver_receipt_chain

from ._world import (
    DESTINATION,
    METHOD,
    NOW,
    OPERATION,
    ORG,
    PARAMETERS,
    PATH,
    RECEIVER,
    World,
    wire_for,
)

KEYS = {OPERATION: "invoiceId"}
DECISION = sha256_digest({"decision": "approved-once"})
APPROVAL = sha256_digest({"approval": "one-human-approval"})


def _send(world, permit, params=None):
    params = dict(PARAMETERS if params is None else params)
    return world.gate.check(
        method=METHOD,
        path=PATH,
        headers=[(PERMIT_HEADER, encode_permit_header(permit))],
        body=wire_for(params),
        received_at=NOW,
    )


def _chain_ok(world):
    report = verify_receiver_receipt_chain(
        list(world.ledger.iter_receipts()),
        receiver_public_keys=world.published_keys,
        receiver_id=RECEIVER,
    )
    assert report.ok, report.failures


def test_second_permit_for_the_same_decision_is_refused_and_not_consumed(tmp_path):
    """What a deleted execution_authorization_mint row on the agent side
    produces: a second, different permit for one decision."""
    w = World(tmp_path)
    first = w.permit(decision_receipt_digest=DECISION)
    assert _send(w, first).admitted
    second = w.permit(decision_receipt_digest=DECISION)
    assert second["execution_authorization_id"] != first["execution_authorization_id"]
    refused = _send(w, second)
    assert not refused.admitted
    assert refused.reason_code == g.RECEIVER_DUPLICATE_DECISION
    assert refused.http_status == 409
    assert refused.receipt["outcome"] == "REFUSED"
    assert refused.receipt["reason_code"] == g.RECEIVER_DUPLICATE_DECISION
    assert not w.ledger.is_consumed(ORG, second["execution_authorization_id"])
    assert (
        w.ledger.source_holder(ORG, "decision", DECISION)
        == (first["execution_authorization_id"])
    )
    _chain_ok(w)


def test_second_permit_under_the_same_approval_is_refused(tmp_path):
    """What a deleted approval_consume row produces: one human approval,
    two decisions, two permits."""
    w = World(tmp_path)
    assert _send(w, w.permit(approval_artifact_digest=APPROVAL)).admitted
    refused = _send(w, w.permit(approval_artifact_digest=APPROVAL))
    assert not refused.admitted
    assert refused.reason_code == g.RECEIVER_DUPLICATE_APPROVAL
    assert refused.http_status == 409
    _chain_ok(w)


def test_permits_without_an_approval_are_judged_by_decision_alone(tmp_path):
    w = World(tmp_path)
    assert _send(w, w.permit(approval_artifact_digest=None)).admitted
    assert _send(w, w.permit(approval_artifact_digest=None)).admitted
    again = _send(
        w, w.permit(approval_artifact_digest=None, decision_receipt_digest=DECISION)
    )
    assert again.admitted
    refused = _send(
        w, w.permit(approval_artifact_digest=None, decision_receipt_digest=DECISION)
    )
    assert refused.reason_code == g.RECEIVER_DUPLICATE_DECISION


def test_replaying_one_permit_is_still_permit_consumed(tmp_path):
    w = World(tmp_path)
    permit = w.permit(
        decision_receipt_digest=DECISION, approval_artifact_digest=APPROVAL
    )
    assert _send(w, permit).admitted
    replay = _send(w, permit)
    assert replay.reason_code == g.RECEIVER_PERMIT_CONSUMED


def test_the_claim_holds_without_a_business_key(tmp_path):
    """The case ADR 0030's keys did not cover: an operation with no
    declared key. Both permits used to execute."""
    w = World(tmp_path)  # no transaction_keys
    assert _send(w, w.permit(decision_receipt_digest=DECISION)).admitted
    refused = _send(w, w.permit(decision_receipt_digest=DECISION))
    assert refused.reason_code == g.RECEIVER_DUPLICATE_DECISION
    assert refused.transaction is None


def test_a_different_invoice_under_the_same_approval_is_still_refused(tmp_path):
    """The business key differs, so ADR 0030 alone would admit it."""
    w = World(tmp_path, transaction_keys=KEYS)
    first_params = {**PARAMETERS, "invoiceId": "INV-1001"}
    other_params = {**PARAMETERS, "invoiceId": "INV-2002"}
    assert _send(
        w,
        w.permit(parameters=first_params, approval_artifact_digest=APPROVAL),
        first_params,
    ).admitted
    refused = _send(
        w,
        w.permit(parameters=other_params, approval_artifact_digest=APPROVAL),
        other_params,
    )
    assert refused.reason_code == g.RECEIVER_DUPLICATE_APPROVAL
    assert w.ledger.transactions() and len(w.ledger.transactions()) == 1


def test_concurrent_permits_for_one_decision_admit_one(tmp_path):
    w = World(tmp_path)
    other = ReceiverGate(
        receiver_id=RECEIVER,
        destinations=frozenset({DESTINATION}),
        trust_bundle=w.bundle,
        ledger=ReceiverLedger(w.ledger_path),
        receipt_signing_key=w.receipt_key,
        receipt_key_id="bank-receiver-01",
    )
    permits = [w.permit(decision_receipt_digest=DECISION) for _ in range(16)]
    results = []
    barrier = threading.Barrier(16)

    def worker(i):
        gate = w.gate if i % 2 else other
        barrier.wait()
        results.append(
            gate.check(
                method=METHOD,
                path=PATH,
                headers=[(PERMIT_HEADER, encode_permit_header(permits[i]))],
                body=wire_for(PARAMETERS),
                received_at=NOW,
            )
        )

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(r.admitted for r in results) == 1
    assert {r.reason_code for r in results if not r.admitted} == {
        g.RECEIVER_DUPLICATE_DECISION
    }
    _chain_ok(w)


def test_an_existing_ledger_is_upgraded_on_open(tmp_path):
    """A receiver ledger written before this change has no sources table."""
    w = World(tmp_path)
    assert _send(w, w.permit()).admitted
    with sqlite3.connect(w.ledger_path) as conn:
        conn.execute("DROP TABLE receiver_sources")
    reopened = World.__new__(World)
    reopened.__dict__.update(w.__dict__)
    reopened.ledger = ReceiverLedger(w.ledger_path)
    reopened.gate.ledger = reopened.ledger
    assert _send(reopened, reopened.permit(decision_receipt_digest=DECISION)).admitted
    refused = _send(reopened, reopened.permit(decision_receipt_digest=DECISION))
    assert refused.reason_code == g.RECEIVER_DUPLICATE_DECISION
    _chain_ok(reopened)
