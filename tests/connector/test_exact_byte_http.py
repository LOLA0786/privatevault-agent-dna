"""Exact-byte egress adapter — last meter of the dispatch boundary.

Claims → tests:
  - Happy path sends exact bytes and consumes EA
    → test_happy_path_sends_and_consumes
  - Payload mutation after EA issuance never calls send
    → test_mutated_payload_never_calls_send
  - Second consumption fails and never calls send again
    → test_second_consume_fails
  - Invalid / expired / missing EA fails closed
    → test_missing_authorization_fails_closed
    → test_invalid_trust_bundle_fails_closed
    → test_expired_authorization_fails_closed
  - Attacker-controlled trust bundle is rejected
    → test_attacker_controlled_trust_bundle_never_sends
  - Caller-supplied peer identity is refused
    → test_caller_supplied_peer_identity_is_refused
  - Transport writes then raises → INDETERMINATE, no retry
    → test_transport_write_then_raise_is_indeterminate
  - Pre-send handshake failure does not consume
    → test_pre_send_control_failure_does_not_consume
  - Duplicate dispatch
    → test_duplicate_dispatch_is_consumed
  - Destination substitution
    → test_destination_substitution_never_sends
  - Callback sending different bytes is not EXECUTED
    → test_callback_sending_different_bytes_is_not_executed
  - Verified sidecar witness and closure
    → test_verified_sidecar_witness_and_closure_happy_path
"""

from __future__ import annotations

import copy
import uuid
from datetime import datetime
from typing import Any

import pytest
from nacl.signing import SigningKey

from agent_dna.authority_v01 import (
    CANONICALIZATION,
    TRUST_SPEC,
    encode_public_key,
    sha256_digest,
)
from agent_dna.authorize_binding import EXECUTION_AUTHORIZATION_CONSUMED
from agent_dna.closure_v01 import verify_closure_chain
from agent_dna.connector.adapters.exact_byte_http import (
    DISPATCH_BYTES_MISMATCH,
    DISPATCH_CALLER_PEER_REFUSED,
    DISPATCH_CALLER_SEND_REFUSED,
    DISPATCH_CALLER_TRUST_REFUSED,
    DISPATCH_CREDENTIAL_MISMATCH,
    DISPATCH_HANDSHAKE_FAILED,
    DISPATCH_TRANSPORT_REFUSED,
    OUTCOME_CONTROL_FAILURE,
    OUTCOME_EXECUTED,
    OUTCOME_INDETERMINATE,
    ExactByteContext,
    ExactByteHttpDispatcher,
    RecordingSidecarTransport,
    WitnessSigner,
    serialize_json_payload,
)
from agent_dna.connector.adapters.sidecar_transport import CallbackSidecarTransport
from agent_dna.dispatch_v01 import verify_dispatch_witness
from agent_dna.execution_v01 import (
    EXECUTION_AUTHORIZATION_SPEC,
    sha256_bytes_digest,
    sign_execution_authorization,
)
from agent_dna.sqlite_store import SQLiteDecisionStore

Z = "sha256:" + ("0" * 64)
ONE = "sha256:" + ("1" * 64)
ORG = "egress.example"
PAYLOAD = {"account": "4471", "amount": 400000, "currency": "INR"}
WIRE = serialize_json_payload(PAYLOAD)
PEER = b"tls-spki:payments.store.example:v3"
AT = "2026-08-10T12:00:05Z"


def _bundle_for(runtime_key: SigningKey, witness_key: SigningKey) -> dict[str, Any]:
    return {
        "spec": TRUST_SPEC,
        "canonicalization": CANONICALIZATION,
        "organisation_id": ORG,
        "bundle_version": 1,
        "pinned_at": "2026-08-10T11:00:00Z",
        "keys": [
            {
                "key_id": "ea-signer",
                "principal": f"execution-runtime@{ORG}",
                "algorithm": "ed25519",
                "public_key": encode_public_key(runtime_key),
                "usages": ["execution_authorization_signer"],
            },
            {
                "key_id": "witness-01",
                "principal": f"egress-witness@{ORG}",
                "algorithm": "ed25519",
                "public_key": encode_public_key(witness_key),
                "usages": ["dispatch_witness_signer", "closure_signer"],
            },
        ],
    }


def _world(tmp_path, *, expires_at: str = "2099-01-01T00:00:00Z"):
    runtime_key = SigningKey.generate()
    witness_key = SigningKey.generate()
    trust_bundle = _bundle_for(runtime_key, witness_key)
    action = {
        "subject_principal": f"treasury@{ORG}",
        "subject_key_id": "treasury",
        "action": "payments.initiate_wire",
        "resource": "payments:wire",
        "parameters": {"amount": 400000},
    }
    dispatch = {
        "transport": "https",
        "destination": "payments.store.example",
        "operation": "POST /v1/wires",
        "wire_content_type": "application/json",
        "wire_content_encoding": "identity",
        "tool_id": "payments.initiate_wire.v1",
        "tool_schema_digest": Z,
        "tool_artifact_digest": ONE,
        "credential_audience": "payments.store.example",
        "idempotency_key_digest": Z,
        "retry_policy_digest": ONE,
        "serialization": "pv-json-parameters/0.1",
    }
    ea_id = f"eauth-{uuid.uuid4()}"
    authorization = sign_execution_authorization(
        {
            "spec": EXECUTION_AUTHORIZATION_SPEC,
            "canonicalization": CANONICALIZATION,
            "execution_authorization_id": ea_id,
            "organisation_id": ORG,
            "request_id": "req-egress-1",
            "issued_at": "2026-08-10T12:00:00Z",
            "not_before": "2026-08-10T12:00:00Z",
            "expires_at": expires_at,
            "nonce": uuid.uuid4().hex,
            "decision_receipt_digest": Z,
            "authority_receipt_digest": ONE,
            "approval_artifact_digest": Z,
            "action": action,
            "action_digest": sha256_digest(action),
            "expected_wire_bytes_digest": sha256_bytes_digest(WIRE),
            "expected_wire_bytes_length": len(WIRE),
            "expected_peer_identity_digest": sha256_bytes_digest(PEER),
            "dispatch": dispatch,
            "state_snapshot_digest": Z,
            "policy_bundle_digest": ONE,
            "trust_bundle_digest": sha256_digest(trust_bundle),
            "obligations_digest": Z,
            "max_uses": 1,
            "signer_key_id": "ea-signer",
        },
        runtime_key,
    )
    store = SQLiteDecisionStore(str(tmp_path / "consume.db"))
    return {
        "authorization": authorization,
        "trust_bundle": trust_bundle,
        "action": action,
        "dispatch": dispatch,
        "witness_key": witness_key,
        "runtime_key": runtime_key,
        "store": store,
        "ea_id": ea_id,
    }


def _context(w, *, at_time: str = AT, dispatch: dict | None = None) -> ExactByteContext:
    return ExactByteContext(
        request_id="req-egress-1",
        observed_action=copy.deepcopy(w["action"]),
        observed_dispatch=copy.deepcopy(dispatch or w["dispatch"]),
        decision_receipt_digest=Z,
        authority_receipt_digest=ONE,
        approval_artifact_digest=Z,
        state_snapshot_digest=Z,
        policy_bundle_digest=ONE,
        obligations_digest=Z,
        at_time=at_time,
    )


def _dispatcher(w, transport) -> ExactByteHttpDispatcher:
    return ExactByteHttpDispatcher(
        consume_ledger=w["store"],
        witness=WitnessSigner(
            signing_key=w["witness_key"],
            signer_key_id="witness-01",
            witness_component_id="exact-byte-http-test",
            closure_signer_key_id="witness-01",
            closure_signing_key=w["witness_key"],
        ),
        trust_bundle=w["trust_bundle"],
        transport=transport,
    )


def test_happy_path_sends_and_consumes(tmp_path):
    w = _world(tmp_path)
    transport = RecordingSidecarTransport(peer_identity=PEER)
    result = _dispatcher(w, transport).dispatch(
        authorization=w["authorization"],
        payload=PAYLOAD,
        context=_context(w),
        observed_at=AT,
    )
    assert result.sent is True
    assert result.outcome == OUTCOME_EXECUTED
    assert result.tool_executed is True
    assert result.retryable is False
    assert transport.writes == [WIRE]
    assert result.wire_bytes == WIRE
    assert result.closure is not None
    assert result.closure["response_status"] == str(transport.http_status)
    assert result.closure["dispatch_outcome"] == "ACKNOWLEDGED"
    assert transport.handshake_count == 1
    assert transport.close_count == 1
    assert w["store"].is_execution_authorization_consumed(w["ea_id"])
    assert result.witness is not None
    boundary = verify_dispatch_witness(
        result.witness,
        w["authorization"],
        w["trust_bundle"],
        observed_action=w["action"],
        observed_dispatch=w["dispatch"],
        wire_bytes=WIRE,
        peer_identity_bytes=PEER,
    )
    assert boundary.ok


def test_mutated_payload_never_calls_send(tmp_path):
    w = _world(tmp_path)
    transport = RecordingSidecarTransport(peer_identity=PEER)
    tampered = {"account": "4471", "amount": 900000, "currency": "INR"}
    result = _dispatcher(w, transport).dispatch(
        authorization=w["authorization"],
        payload=tampered,
        context=_context(w),
        observed_at=AT,
    )
    assert result.sent is False
    assert transport.writes == []
    assert transport.handshake_count == 0
    assert result.reason_code == "EXECUTION_AUTHORIZATION_NON_CONFORMANT"
    assert not w["store"].is_execution_authorization_consumed(w["ea_id"])


def test_second_consume_fails(tmp_path):
    w = _world(tmp_path)
    transport = RecordingSidecarTransport(peer_identity=PEER)
    d = _dispatcher(w, transport)
    first = d.dispatch(
        authorization=w["authorization"],
        wire_bytes=WIRE,
        context=_context(w),
        observed_at=AT,
    )
    assert first.sent is True
    assert len(transport.writes) == 1
    second = d.dispatch(
        authorization=w["authorization"],
        wire_bytes=WIRE,
        context=_context(w),
        observed_at=AT,
    )
    assert second.sent is False
    assert len(transport.writes) == 1
    assert second.reason_code == EXECUTION_AUTHORIZATION_CONSUMED


def test_missing_authorization_fails_closed(tmp_path):
    w = _world(tmp_path)
    transport = RecordingSidecarTransport(peer_identity=PEER)
    result = _dispatcher(w, transport).dispatch(
        authorization={},
        wire_bytes=WIRE,
        context=_context(w),
        observed_at=AT,
    )
    assert result.sent is False
    assert transport.writes == []
    assert transport.handshake_count == 0
    assert result.reason_code is not None


def test_invalid_trust_bundle_fails_closed(tmp_path):
    w = _world(tmp_path)
    transport = RecordingSidecarTransport(peer_identity=PEER)
    broken = copy.deepcopy(w["trust_bundle"])
    broken["keys"] = [broken["keys"][0]]
    with pytest.raises(RuntimeError, match="missing required key usages"):
        ExactByteHttpDispatcher(
            consume_ledger=w["store"],
            witness=WitnessSigner(
                signing_key=w["witness_key"],
                signer_key_id="witness-01",
                witness_component_id="exact-byte-http-test",
            ),
            trust_bundle=broken,
            transport=transport,
        )


def test_expired_authorization_fails_closed(tmp_path):
    w = _world(tmp_path, expires_at="2026-08-10T12:00:01Z")
    transport = RecordingSidecarTransport(peer_identity=PEER)
    result = _dispatcher(w, transport).dispatch(
        authorization=w["authorization"],
        wire_bytes=WIRE,
        context=_context(w, at_time="2026-08-10T12:00:05Z"),
        observed_at=AT,
    )
    assert result.sent is False
    assert transport.writes == []
    assert transport.handshake_count == 0
    assert result.reason_code == "EXECUTION_AUTHORIZATION_NON_CONFORMANT"
    assert not w["store"].is_execution_authorization_consumed(w["ea_id"])


def test_attacker_controlled_trust_bundle_never_sends(tmp_path):
    w = _world(tmp_path)
    attacker_runtime = SigningKey.generate()
    attacker_witness = SigningKey.generate()
    attacker_bundle = _bundle_for(attacker_runtime, attacker_witness)
    attacker_bundle["organisation_id"] = "attacker.example"
    attacker_action = {
        **w["action"],
        "subject_principal": "treasury@attacker.example",
    }
    attacker_auth = sign_execution_authorization(
        {
            **{k: v for k, v in w["authorization"].items() if k != "signature"},
            "organisation_id": "attacker.example",
            "execution_authorization_id": f"eauth-attacker-{uuid.uuid4()}",
            "nonce": uuid.uuid4().hex,
            "signer_key_id": "ea-signer",
            "trust_bundle_digest": sha256_digest(attacker_bundle),
            "action": attacker_action,
            "action_digest": sha256_digest(attacker_action),
        },
        attacker_runtime,
    )
    transport = RecordingSidecarTransport(peer_identity=PEER)
    production = _dispatcher(w, transport)
    stuffed = production.dispatch(
        authorization=attacker_auth,
        wire_bytes=WIRE,
        context=_context(w),
        observed_at=AT,
        trust_bundle=attacker_bundle,
    )
    assert stuffed.reason_code == DISPATCH_CALLER_TRUST_REFUSED
    assert transport.writes == []
    assert transport.handshake_count == 0
    result = production.dispatch(
        authorization=attacker_auth,
        wire_bytes=WIRE,
        context=_context(w),
        observed_at=AT,
    )
    assert result.sent is False
    assert result.outcome == OUTCOME_CONTROL_FAILURE
    assert transport.writes == []
    assert transport.handshake_count == 0
    assert not w["store"].is_execution_authorization_consumed(w["ea_id"])
    assert not w["store"].is_execution_authorization_consumed(
        attacker_auth["execution_authorization_id"]
    )


def test_caller_supplied_send_callback_is_refused(tmp_path):
    w = _world(tmp_path)
    transport = RecordingSidecarTransport(peer_identity=PEER)
    result = _dispatcher(w, transport).dispatch(
        authorization=w["authorization"],
        wire_bytes=WIRE,
        context=_context(w),
        observed_at=AT,
        send=lambda wire, _d: None,
    )
    assert result.reason_code == DISPATCH_CALLER_SEND_REFUSED
    assert result.outcome == OUTCOME_CONTROL_FAILURE
    assert transport.writes == []
    assert transport.handshake_count == 0
    assert not w["store"].is_execution_authorization_consumed(w["ea_id"])


def test_caller_supplied_peer_identity_is_refused(tmp_path):
    w = _world(tmp_path)
    transport = RecordingSidecarTransport(peer_identity=PEER)
    fake = b"attacker-chosen-peer"
    result = _dispatcher(w, transport).dispatch(
        authorization=w["authorization"],
        wire_bytes=WIRE,
        context=_context(w),
        observed_at=AT,
        peer_identity_bytes=fake,
    )
    assert result.reason_code == DISPATCH_CALLER_PEER_REFUSED
    assert result.outcome == OUTCOME_CONTROL_FAILURE
    assert transport.writes == []
    assert transport.handshake_count == 0
    assert not w["store"].is_execution_authorization_consumed(w["ea_id"])


def test_transport_write_then_raise_is_indeterminate(tmp_path):
    w = _world(tmp_path)
    transport = RecordingSidecarTransport(
        peer_identity=PEER,
        write_error=TimeoutError("upstream reset"),
    )
    result = _dispatcher(w, transport).dispatch(
        authorization=w["authorization"],
        wire_bytes=WIRE,
        context=_context(w),
        observed_at=AT,
    )
    assert result.outcome == OUTCOME_INDETERMINATE
    assert result.tool_executed is None
    assert result.retryable is False
    assert result.reason_code == DISPATCH_TRANSPORT_REFUSED
    assert transport.writes == [WIRE]
    assert w["store"].is_execution_authorization_consumed(w["ea_id"])


def test_pre_send_control_failure_does_not_consume(tmp_path):
    w = _world(tmp_path)
    transport = RecordingSidecarTransport(
        peer_identity=PEER,
        handshake_error=ConnectionError("tls handshake refused"),
    )
    result = _dispatcher(w, transport).dispatch(
        authorization=w["authorization"],
        wire_bytes=WIRE,
        context=_context(w),
        observed_at=AT,
    )
    assert result.outcome == OUTCOME_CONTROL_FAILURE
    assert result.tool_executed is False
    assert result.reason_code == DISPATCH_HANDSHAKE_FAILED
    assert transport.writes == []
    assert not w["store"].is_execution_authorization_consumed(w["ea_id"])


def test_duplicate_dispatch_is_consumed(tmp_path):
    test_second_consume_fails(tmp_path)


def test_destination_substitution_never_sends(tmp_path):
    w = _world(tmp_path)
    transport = RecordingSidecarTransport(peer_identity=PEER)
    swapped = copy.deepcopy(w["dispatch"])
    swapped["destination"] = "evil.example"
    result = _dispatcher(w, transport).dispatch(
        authorization=w["authorization"],
        wire_bytes=WIRE,
        context=_context(w, dispatch=swapped),
        observed_at=AT,
    )
    assert result.sent is False
    assert result.reason_code == "DISPATCH_DESTINATION_MISMATCH"
    assert transport.writes == []
    assert transport.handshake_count == 0
    assert not w["store"].is_execution_authorization_consumed(w["ea_id"])


def test_callback_sending_different_bytes_is_not_executed(tmp_path):
    w = _world(tmp_path)
    transport = RecordingSidecarTransport(
        peer_identity=PEER,
        substitute_bytes=b'{"amount":1}',
    )
    result = _dispatcher(w, transport).dispatch(
        authorization=w["authorization"],
        wire_bytes=WIRE,
        context=_context(w),
        observed_at=AT,
    )
    assert result.outcome == OUTCOME_INDETERMINATE
    assert result.tool_executed is None
    assert result.retryable is False
    assert result.reason_code == DISPATCH_BYTES_MISMATCH
    assert result.sent is False
    assert result.witness is None


def test_verified_sidecar_witness_and_closure_happy_path(tmp_path):
    w = _world(tmp_path)
    transport = RecordingSidecarTransport(peer_identity=PEER)
    result = _dispatcher(w, transport).dispatch(
        authorization=w["authorization"],
        wire_bytes=WIRE,
        context=_context(w),
        observed_at=AT,
    )
    assert result.outcome == OUTCOME_EXECUTED
    assert result.witness is not None
    assert result.closure is not None
    assert result.closure["response_status"] == str(transport.http_status)
    assert result.closure["dispatch_outcome"] == "ACKNOWLEDGED"
    boundary = verify_dispatch_witness(
        result.witness,
        w["authorization"],
        w["trust_bundle"],
        observed_action=w["action"],
        observed_dispatch=w["dispatch"],
        wire_bytes=WIRE,
        peer_identity_bytes=PEER,
    )
    assert boundary.ok
    chain = verify_closure_chain(
        w["authorization"],
        result.witness,
        result.closure,
        w["trust_bundle"],
    )
    assert chain.ok


def test_production_rejects_callback_transport_without_test_flag(tmp_path):
    w = _world(tmp_path)
    with pytest.raises(RuntimeError, match="callback SendFn transport is test-only"):
        ExactByteHttpDispatcher(
            consume_ledger=w["store"],
            witness=WitnessSigner(
                signing_key=w["witness_key"],
                signer_key_id="witness-01",
                witness_component_id="x",
            ),
            trust_bundle=w["trust_bundle"],
            transport=CallbackSidecarTransport(
                send=lambda wire, _d: None,
                peer_identity=PEER,
            ),
        )


def test_ledger_failure_after_handshake_closes_session(tmp_path):
    w = _world(tmp_path)

    class _BoomLedger:
        def try_consume_execution_authorization(self, *args, **kwargs):
            raise RuntimeError("ledger unavailable")

    transport = RecordingSidecarTransport(peer_identity=PEER)
    result = ExactByteHttpDispatcher(
        consume_ledger=_BoomLedger(),
        witness=WitnessSigner(
            signing_key=w["witness_key"],
            signer_key_id="witness-01",
            witness_component_id="exact-byte-http-test",
            closure_signer_key_id="witness-01",
            closure_signing_key=w["witness_key"],
        ),
        trust_bundle=w["trust_bundle"],
        transport=transport,
    ).dispatch(
        authorization=w["authorization"],
        wire_bytes=WIRE,
        context=_context(w),
        observed_at=AT,
    )
    assert result.sent is False
    assert result.outcome == OUTCOME_CONTROL_FAILURE
    assert transport.writes == []
    assert transport.handshake_count == 1
    assert transport.close_count == 1


def test_closure_status_follows_transport_http_status(tmp_path):
    w = _world(tmp_path)
    transport = RecordingSidecarTransport(peer_identity=PEER, http_status=401)
    result = _dispatcher(w, transport).dispatch(
        authorization=w["authorization"],
        wire_bytes=WIRE,
        context=_context(w),
        observed_at=AT,
    )
    assert result.outcome == OUTCOME_EXECUTED
    assert result.closure is not None
    assert result.closure["response_status"] == "401"
    assert result.closure["dispatch_outcome"] == "REJECTED"
    chain = verify_closure_chain(
        w["authorization"],
        result.witness,
        result.closure,
        w["trust_bundle"],
    )
    assert chain.ok


def test_credential_audience_mismatch_never_handshakes(tmp_path):
    w = _world(tmp_path)
    transport = RecordingSidecarTransport(
        peer_identity=PEER,
        credentials_headers={"Authorization": "Bearer secret"},
        allowed_destinations=frozenset(["payments.store.example"]),
        allowed_audiences=frozenset(["other.example"]),
    )
    result = _dispatcher(w, transport).dispatch(
        authorization=w["authorization"],
        wire_bytes=WIRE,
        context=_context(w),
        observed_at=AT,
    )
    assert result.sent is False
    assert result.reason_code == DISPATCH_CREDENTIAL_MISMATCH
    assert transport.writes == []
    assert transport.handshake_count == 0
    assert transport.close_count == 0
    assert not w["store"].is_execution_authorization_consumed(w["ea_id"])


def test_witness_and_closure_timestamps_are_monotonic(tmp_path):
    w = _world(tmp_path)
    transport = RecordingSidecarTransport(peer_identity=PEER)
    result = _dispatcher(w, transport).dispatch(
        authorization=w["authorization"],
        wire_bytes=WIRE,
        context=_context(w),
        observed_at=AT,
    )
    assert result.outcome == OUTCOME_EXECUTED
    assert result.witness is not None
    assert result.closure is not None
    observed = result.witness["observed_at"]
    closed = result.closure["closed_at"]
    assert observed.endswith("Z")
    assert closed.endswith("Z")
    assert "." in observed
    assert "." in closed
    assert datetime.fromisoformat(
        observed.replace("Z", "+00:00")
    ) <= datetime.fromisoformat(closed.replace("Z", "+00:00"))
    assert observed != AT


def test_suspended_agent_permit_is_refused_before_any_byte_is_sent(tmp_path):
    """ADR-0018 PR-J: a valid permit minted before its agent was suspended
    is refused at consume time; the target receives nothing and the
    permit is not burned."""
    from agent_dna.connector.adapters.exact_byte_http import DISPATCH_SUSPENDED

    w = _world(tmp_path)
    w["store"].suspend(
        "agent",
        w["action"]["subject_key_id"],
        reason="group breaker trip",
        suspended_by="operator",
        suspended_at=AT,
    )
    transport = RecordingSidecarTransport(peer_identity=PEER)
    result = _dispatcher(w, transport).dispatch(
        authorization=w["authorization"],
        payload=PAYLOAD,
        context=_context(w),
        observed_at=AT,
    )
    assert result.sent is False
    assert result.reason_code == DISPATCH_SUSPENDED
    assert transport.writes == []
    assert not w["store"].is_execution_authorization_consumed(w["ea_id"])
