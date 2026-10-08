"""Receiver gate (ADR 0019): the system of record refuses unpermitted actions.

Claims → tests:
  - A valid permit is admitted exactly once → test_valid_permit_admitted_once
  - Direct call with no permit (agent bypasses the sidecar) is refused
    → test_direct_call_without_permit_is_refused
  - Replay at the receiver is refused even with no agent-side ledger
    → test_replay_refused_by_receiver_ledger
  - Amount / payee swap with the same permit → test_amount_swap_refused,
    test_payee_swap_refused
  - Permit for another system / route / method → test_*_mismatch_refused
  - Forged, unknown-key, wrong-usage, wrong-bundle permits → test_trust_*
  - Expiry and not-before, bounded skew → test_time_window
  - Signed wire that is not the signed action → test_wire_action_mismatch_refused
  - Refusal does not burn the permit → test_refusal_does_not_burn_permit
  - Concurrency: one admit under contention → test_concurrent_admit_exactly_once
  - Restart keeps consumption → test_consumption_survives_new_ledger_instance
  - Receipt chain independently verifiable; tamper detected
    → test_receipt_chain_verifies, test_receipt_tamper_detected
  - Receiver key independence enforced → test_receipt_key_in_pv_bundle_refused
"""

from __future__ import annotations

import copy
import sqlite3
import threading
from datetime import UTC, datetime, timedelta

import pytest
from nacl.signing import SigningKey

from agent_dna.authority_v01 import canonicalize
from agent_dna.receiver import gate as g
from agent_dna.receiver.gate import ReceiverGate
from agent_dna.receiver.ledger import ReceiverLedger
from agent_dna.receiver.permit_header import (
    PERMIT_HEADER,
    decode_permit_header,
    encode_permit_header,
)
from agent_dna.receiver.receipts import verify_receiver_receipt_chain

from ._world import (
    DESTINATION,
    METHOD,
    NOW,
    ORG,
    PARAMETERS,
    PATH,
    RECEIVER,
    World,
    mint,
    trust_bundle_for,
    wire_for,
)


def _send(world, permit, *, body=None, method=METHOD, path=PATH, headers=None, at=NOW):
    hdrs = [] if permit is None else [(PERMIT_HEADER, encode_permit_header(permit))]
    hdrs += list(headers or [])
    return world.gate.check(
        method=method,
        path=path,
        headers=hdrs,
        body=wire_for(PARAMETERS) if body is None else body,
        received_at=at,
    )


def _chain(world):
    return verify_receiver_receipt_chain(
        list(world.ledger.iter_receipts()),
        receiver_public_keys=world.published_keys,
        receiver_id=RECEIVER,
    )


# ---------------------------------------------------------------- happy path


def test_valid_permit_admitted_once(tmp_path):
    w = World(tmp_path)
    permit = w.permit()
    decision = _send(w, permit)
    assert decision.admitted is True
    assert decision.http_status == 200
    assert decision.receipt["outcome"] == "ADMITTED"
    assert (
        decision.receipt["execution_authorization_id"]
        == (permit["execution_authorization_id"])
    )
    assert decision.receipt["sequence"] == 1
    assert w.ledger.is_consumed(ORG, permit["execution_authorization_id"])


def test_header_round_trip_is_exact():
    signer = SigningKey.generate()
    permit = mint(signer, trust_bundle_for(signer))
    assert decode_permit_header(encode_permit_header(permit)) == permit


# --------------------------------------------------------------- bypass paths


def test_direct_call_without_permit_is_refused(tmp_path):
    w = World(tmp_path)
    decision = _send(w, None)
    assert decision.admitted is False
    assert decision.reason_code == g.RECEIVER_PERMIT_MISSING
    assert decision.http_status == 403
    assert decision.receipt["outcome"] == "REFUSED"
    assert decision.receipt["execution_authorization_id"] is None


def test_two_permit_headers_are_ambiguous(tmp_path):
    w = World(tmp_path)
    a, b = w.permit(), w.permit()
    decision = w.gate.check(
        method=METHOD,
        path=PATH,
        headers=[
            (PERMIT_HEADER, encode_permit_header(a)),
            (PERMIT_HEADER.lower(), encode_permit_header(b)),
        ],
        body=wire_for(PARAMETERS),
        received_at=NOW,
    )
    assert decision.reason_code == g.RECEIVER_PERMIT_AMBIGUOUS
    assert not w.ledger.is_consumed(ORG, a["execution_authorization_id"])


@pytest.mark.parametrize(
    "value",
    ["", "not base64!", "e30", "AAAA====", "eyJhIjoxLCJhIjoyfQ"],
)
def test_malformed_header_refused(tmp_path, value):
    w = World(tmp_path)
    decision = w.gate.check(
        method=METHOD,
        path=PATH,
        headers=[(PERMIT_HEADER, value)],
        body=wire_for(PARAMETERS),
        received_at=NOW,
    )
    assert decision.admitted is False
    assert decision.reason_code in {
        g.RECEIVER_PERMIT_MALFORMED,
        g.RECEIVER_PERMIT_SCHEMA_INVALID,
    }


def test_non_canonical_permit_encoding_refused(tmp_path):
    import base64
    import json

    w = World(tmp_path)
    permit = w.permit()
    loose = json.dumps(permit, indent=1).encode()
    assert loose != canonicalize(permit)
    value = base64.urlsafe_b64encode(loose).decode().rstrip("=")
    decision = w.gate.check(
        method=METHOD,
        path=PATH,
        headers=[(PERMIT_HEADER, value)],
        body=wire_for(PARAMETERS),
        received_at=NOW,
    )
    assert decision.reason_code == g.RECEIVER_PERMIT_MALFORMED


# ------------------------------------------------------------- replay / burn


def test_replay_refused_by_receiver_ledger(tmp_path):
    w = World(tmp_path)
    permit = w.permit()
    assert _send(w, permit).admitted
    again = _send(w, permit)
    assert again.admitted is False
    assert again.reason_code == g.RECEIVER_PERMIT_CONSUMED
    assert again.http_status == 409
    assert again.receipt["outcome"] == "REFUSED"
    assert (
        again.receipt["execution_authorization_id"]
        == (permit["execution_authorization_id"])
    )


def test_refusal_does_not_burn_permit(tmp_path):
    w = World(tmp_path)
    permit = w.permit()
    tampered = wire_for({**PARAMETERS, "transferAmount": 5_000_000})
    assert _send(w, permit, body=tampered).reason_code == g.RECEIVER_WIRE_MISMATCH
    assert not w.ledger.is_consumed(ORG, permit["execution_authorization_id"])
    assert _send(w, permit).admitted is True


def test_consumption_survives_new_ledger_instance(tmp_path):
    w = World(tmp_path)
    permit = w.permit()
    assert _send(w, permit).admitted
    restarted = ReceiverGate(
        receiver_id=RECEIVER,
        destinations=frozenset({DESTINATION}),
        trust_bundle=w.bundle,
        ledger=ReceiverLedger(w.ledger_path),
        receipt_signing_key=w.receipt_key,
        receipt_key_id="bank-receiver-01",
    )
    decision = restarted.check(
        method=METHOD,
        path=PATH,
        headers=[(PERMIT_HEADER, encode_permit_header(permit))],
        body=wire_for(PARAMETERS),
        received_at=NOW,
    )
    assert decision.reason_code == g.RECEIVER_PERMIT_CONSUMED
    assert _chain(w).ok


def test_concurrent_admit_exactly_once(tmp_path):
    w = World(tmp_path)
    permit = w.permit()
    results = []
    barrier = threading.Barrier(16)

    def worker():
        barrier.wait()
        results.append(_send(w, permit))

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    admitted = [r for r in results if r.admitted]
    assert len(admitted) == 1
    assert all(
        r.reason_code == g.RECEIVER_PERMIT_CONSUMED for r in results if not r.admitted
    )
    report = _chain(w)
    assert report.ok, report.failures
    assert report.count == 16


# ------------------------------------------------------- business-field swaps


def test_amount_swap_refused(tmp_path):
    w = World(tmp_path)
    permit = w.permit()
    body = wire_for({**PARAMETERS, "transferAmount": 50_000_000})
    decision = _send(w, permit, body=body)
    assert decision.reason_code == g.RECEIVER_WIRE_MISMATCH


def test_payee_swap_refused(tmp_path):
    w = World(tmp_path)
    permit = w.permit()
    body = wire_for({**PARAMETERS, "toAccountId": "MULE-666"})
    assert _send(w, permit, body=body).reason_code == g.RECEIVER_WIRE_MISMATCH


def test_wire_action_mismatch_refused(tmp_path):
    """A signed permit whose wire digest is a different body than its own
    action parameters (an inconsistent minter) is refused at the receiver."""
    w = World(tmp_path)
    other_body = wire_for({**PARAMETERS, "toAccountId": "MULE-666"})
    permit = w.permit(wire=other_body)
    decision = _send(w, permit, body=other_body)
    assert decision.reason_code == g.RECEIVER_WIRE_ACTION_MISMATCH


# ------------------------------------------------------ wrong system / route


def test_audience_mismatch_refused(tmp_path):
    w = World(tmp_path)
    permit = w.permit(audience="payments-hub.bank.example")
    assert _send(w, permit).reason_code == g.RECEIVER_AUDIENCE_MISMATCH


def test_destination_mismatch_refused(tmp_path):
    w = World(tmp_path)
    permit = w.permit(destination="https://other.bank.example")
    assert _send(w, permit).reason_code == g.RECEIVER_DESTINATION_MISMATCH


def test_path_mismatch_refused(tmp_path):
    w = World(tmp_path)
    permit = w.permit()
    decision = _send(w, permit, path="/api/v1/loans")
    assert decision.reason_code == g.RECEIVER_OPERATION_MISMATCH


def test_query_string_change_refused(tmp_path):
    w = World(tmp_path)
    permit = w.permit()
    decision = _send(w, permit, path=PATH + "?dryRun=false")
    assert decision.reason_code == g.RECEIVER_OPERATION_MISMATCH


def test_method_mismatch_refused(tmp_path):
    w = World(tmp_path)
    permit = w.permit()
    assert _send(w, permit, method="PUT").reason_code == g.RECEIVER_OPERATION_MISMATCH


def test_non_https_permit_refused(tmp_path):
    w = World(tmp_path)
    permit = w.permit(transport="http")
    assert _send(w, permit).reason_code == g.RECEIVER_TRANSPORT_UNSUPPORTED


# -------------------------------------------------------------------- trust


def test_trust_forged_signature_refused(tmp_path):
    w = World(tmp_path)
    forged = mint(SigningKey.generate(), w.bundle)
    assert _send(w, forged).reason_code == g.RECEIVER_PERMIT_SIGNATURE_INVALID


def test_trust_unknown_key_refused(tmp_path):
    w = World(tmp_path)
    permit = w.permit(signer_key_id="someone-else")
    assert _send(w, permit).reason_code == g.RECEIVER_TRUST_ROOT_UNKNOWN


def test_trust_wrong_usage_refused(tmp_path):
    signer = SigningKey.generate()
    bundle = trust_bundle_for(signer, usages=["receipt_signer", "approval_signer"])
    bundle["keys"].append(trust_bundle_for(SigningKey.generate())["keys"][0])
    bundle["keys"][1]["key_id"] = "real-signer"
    gate = ReceiverGate(
        receiver_id=RECEIVER,
        destinations=frozenset({DESTINATION}),
        trust_bundle=bundle,
        ledger=ReceiverLedger(tmp_path / "r.db"),
        receipt_signing_key=SigningKey.generate(),
        receipt_key_id="r",
    )
    permit = mint(signer, bundle)
    decision = gate.check(
        method=METHOD,
        path=PATH,
        headers={PERMIT_HEADER: encode_permit_header(permit)},
        body=wire_for(PARAMETERS),
        received_at=NOW,
    )
    assert decision.reason_code == g.RECEIVER_KEY_USAGE_INVALID


def test_trust_other_bundle_refused(tmp_path):
    w = World(tmp_path)
    permit = w.permit(trust_bundle_digest="sha256:" + "a" * 64)
    assert _send(w, permit).reason_code == g.RECEIVER_TRUST_BUNDLE_MISMATCH


def test_trust_other_organisation_refused(tmp_path):
    w = World(tmp_path)
    permit = w.permit(organisation_id="attacker.example")
    assert _send(w, permit).reason_code == g.RECEIVER_ORGANISATION_MISMATCH


def test_trust_post_signature_edit_refused(tmp_path):
    w = World(tmp_path)
    permit = copy.deepcopy(w.permit())
    permit["expires_at"] = "2099-01-01T00:00:00Z"
    assert _send(w, permit).reason_code == g.RECEIVER_PERMIT_SIGNATURE_INVALID


# --------------------------------------------------------------------- time


def test_time_window(tmp_path):
    w = World(tmp_path)
    expired = w.permit(expires_at="2026-10-08T12:00:20Z")
    assert _send(w, expired).reason_code == g.RECEIVER_PERMIT_EXPIRED
    early = w.permit(
        not_before="2026-10-08T12:00:40Z", expires_at="2026-10-08T12:02:00Z"
    )
    assert _send(w, early).reason_code == g.RECEIVER_PERMIT_NOT_YET_VALID
    at_expiry = w.permit(expires_at="2026-10-08T12:00:30Z")
    assert _send(w, at_expiry).reason_code == g.RECEIVER_PERMIT_EXPIRED


def test_bounded_skew_admits_near_boundary(tmp_path):
    w = World(tmp_path, clock_skew=timedelta(seconds=15))
    early = w.permit(
        not_before="2026-10-08T12:00:40Z", expires_at="2026-10-08T12:02:00Z"
    )
    assert _send(w, early).admitted


def test_skew_over_bound_refused_at_config(tmp_path):
    with pytest.raises(ValueError):
        World(tmp_path, clock_skew=timedelta(minutes=5))


# ---------------------------------------------------------- body handling


def test_content_encoding_refused(tmp_path):
    w = World(tmp_path)
    decision = _send(w, w.permit(), headers=[("Content-Encoding", "gzip")])
    assert decision.reason_code == g.RECEIVER_CONTENT_ENCODING_REFUSED


def test_body_over_bound_refused(tmp_path):
    w = World(tmp_path, max_body_bytes=8)
    decision = _send(w, w.permit())
    assert decision.reason_code == g.RECEIVER_BODY_TOO_LARGE
    assert decision.http_status == 413


# ----------------------------------------------------------- local policy


def _payee_allowlist(action, _dispatch):
    if action["parameters"].get("toAccountId") not in {"B-2002"}:
        return "payee not on bank allowlist"
    return None


def test_local_policy_can_refuse_a_valid_permit(tmp_path):
    w = World(tmp_path, local_checks=(_payee_allowlist,))
    permit = w.permit(parameters={**PARAMETERS, "toAccountId": "C-3003"})
    body = wire_for({**PARAMETERS, "toAccountId": "C-3003"})
    decision = _send(w, permit, body=body)
    assert decision.reason_code == g.RECEIVER_LOCAL_POLICY_REFUSED
    assert _send(w, w.permit()).admitted


def test_local_policy_exception_refuses(tmp_path):
    def broken(_a, _d):
        raise KeyError("boom")

    w = World(tmp_path, local_checks=(broken,))
    assert _send(w, w.permit()).reason_code == g.RECEIVER_LOCAL_POLICY_REFUSED


# --------------------------------------------------------- config refusals


def test_receipt_key_in_pv_bundle_refused(tmp_path):
    signer = SigningKey.generate()
    with pytest.raises(ValueError, match="independent key"):
        ReceiverGate(
            receiver_id=RECEIVER,
            destinations=frozenset({DESTINATION}),
            trust_bundle=trust_bundle_for(signer),
            ledger=ReceiverLedger(tmp_path / "r.db"),
            receipt_signing_key=signer,
            receipt_key_id="r",
        )


def test_unprotected_write_operation_refused_at_config(tmp_path):
    with pytest.raises(ValueError, match="GET/HEAD"):
        World(tmp_path, unprotected_operations=frozenset({"POST /anything"}))


def test_unprotected_read_passes_without_receipt(tmp_path):
    w = World(tmp_path, unprotected_operations=frozenset({"GET /health"}))
    decision = w.gate.check(method="GET", path="/health", headers=[], body=b"")
    assert decision.admitted and decision.receipt is None
    blocked = w.gate.check(method="GET", path="/clients", headers=[], body=b"")
    assert blocked.reason_code == g.RECEIVER_PERMIT_MISSING


# ------------------------------------------------------- ledger failure


def test_ledger_failure_refuses(tmp_path, monkeypatch):
    w = World(tmp_path)

    def boom(**_kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(w.ledger, "record", boom)
    decision = _send(w, w.permit())
    assert decision.admitted is False
    assert decision.reason_code == g.RECEIVER_LEDGER_UNAVAILABLE
    assert decision.http_status == 503


def test_internal_error_refuses(tmp_path, monkeypatch):
    w = World(tmp_path)
    monkeypatch.setattr(
        w.gate, "_verify_body", lambda *_a: (_ for _ in ()).throw(RuntimeError())
    )
    decision = _send(w, w.permit())
    assert decision.admitted is False
    assert decision.reason_code == g.RECEIVER_INTERNAL_ERROR


# --------------------------------------------------------------- receipts


def test_receipt_chain_verifies(tmp_path):
    w = World(tmp_path)
    permit = w.permit()
    _send(w, None)
    _send(w, permit)
    _send(w, permit)
    report = _chain(w)
    assert report.ok, report.failures
    assert report.count == 3
    outcomes = [r["outcome"] for r in w.ledger.iter_receipts()]
    assert outcomes == ["REFUSED", "ADMITTED", "REFUSED"]


def test_receipt_tamper_detected(tmp_path):
    w = World(tmp_path)
    _send(w, w.permit())
    _send(w, None)
    receipts = list(w.ledger.iter_receipts())
    receipts[0]["outcome"] = "REFUSED"
    receipts[0]["reason_code"] = "RECEIVER_PERMIT_MISSING"
    report = verify_receiver_receipt_chain(
        receipts, receiver_public_keys=w.published_keys, receiver_id=RECEIVER
    )
    assert not report.ok


def test_receipt_dropped_entry_detected(tmp_path):
    w = World(tmp_path)
    for _ in range(3):
        _send(w, None)
    receipts = list(w.ledger.iter_receipts())
    del receipts[1]
    report = verify_receiver_receipt_chain(
        receipts, receiver_public_keys=w.published_keys, receiver_id=RECEIVER
    )
    assert not report.ok


def test_receipt_unpublished_key_detected(tmp_path):
    w = World(tmp_path)
    _send(w, w.permit())
    report = verify_receiver_receipt_chain(
        list(w.ledger.iter_receipts()),
        receiver_public_keys={"bank-receiver-01": "A" * 43 + "="},
        receiver_id=RECEIVER,
    )
    assert not report.ok


def test_received_at_recorded_in_utc(tmp_path):
    w = World(tmp_path)
    decision = _send(w, w.permit(), at=datetime(2026, 10, 8, 12, 0, 30, tzinfo=UTC))
    assert decision.receipt["received_at"].startswith("2026-10-08T12:00:30")
