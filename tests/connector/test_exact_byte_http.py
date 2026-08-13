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
"""

from __future__ import annotations

import copy
import uuid
from typing import Any

from nacl.signing import SigningKey

from agent_dna.authority_v01 import (
    CANONICALIZATION,
    TRUST_SPEC,
    encode_public_key,
    sha256_digest,
)
from agent_dna.authorize_binding import EXECUTION_AUTHORIZATION_CONSUMED
from agent_dna.connector.adapters.exact_byte_http import (
    ExactByteContext,
    ExactByteHttpDispatcher,
    WitnessSigner,
    serialize_json_payload,
)
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


class _CountingSend:
    """Transport stub that records every invocation."""

    def __init__(self) -> None:
        self.calls: list[bytes] = []

    def __call__(self, wire: bytes, _dispatch: Any) -> dict[str, Any]:
        self.calls.append(wire)
        return {"status": "ok", "length": len(wire)}


def _world(tmp_path, *, expires_at: str = "2026-08-10T12:10:00Z"):
    runtime_key = SigningKey.generate()
    witness_key = SigningKey.generate()
    trust_bundle = {
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
                "usages": ["dispatch_witness_signer"],
            },
        ],
    }
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
        "store": store,
        "ea_id": ea_id,
    }


def _context(w, *, at_time: str = AT) -> ExactByteContext:
    return ExactByteContext(
        request_id="req-egress-1",
        observed_action=copy.deepcopy(w["action"]),
        observed_dispatch=copy.deepcopy(w["dispatch"]),
        decision_receipt_digest=Z,
        authority_receipt_digest=ONE,
        approval_artifact_digest=Z,
        state_snapshot_digest=Z,
        policy_bundle_digest=ONE,
        obligations_digest=Z,
        at_time=at_time,
    )


def _dispatcher(w, send) -> ExactByteHttpDispatcher:
    return ExactByteHttpDispatcher(
        consume_ledger=w["store"],
        witness=WitnessSigner(
            signing_key=w["witness_key"],
            signer_key_id="witness-01",
            witness_component_id="exact-byte-http-test",
        ),
        send=send,
    )


def test_happy_path_sends_and_consumes(tmp_path):
    w = _world(tmp_path)
    send = _CountingSend()
    result = _dispatcher(w, send).dispatch(
        authorization=w["authorization"],
        trust_bundle=w["trust_bundle"],
        payload=PAYLOAD,
        peer_identity_bytes=PEER,
        context=_context(w),
        observed_at=AT,
    )
    assert result.sent is True
    assert send.calls == [WIRE]
    assert result.wire_bytes == WIRE
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
    send = _CountingSend()
    tampered = {"account": "4471", "amount": 900000, "currency": "INR"}
    result = _dispatcher(w, send).dispatch(
        authorization=w["authorization"],
        trust_bundle=w["trust_bundle"],
        payload=tampered,
        peer_identity_bytes=PEER,
        context=_context(w),
        observed_at=AT,
    )
    assert result.sent is False
    assert send.calls == []
    assert result.reason_code == "EXECUTION_AUTHORIZATION_NON_CONFORMANT"
    assert not w["store"].is_execution_authorization_consumed(w["ea_id"])


def test_second_consume_fails(tmp_path):
    w = _world(tmp_path)
    send = _CountingSend()
    d = _dispatcher(w, send)
    first = d.dispatch(
        authorization=w["authorization"],
        trust_bundle=w["trust_bundle"],
        wire_bytes=WIRE,
        peer_identity_bytes=PEER,
        context=_context(w),
        observed_at=AT,
    )
    assert first.sent is True
    assert len(send.calls) == 1
    second = d.dispatch(
        authorization=w["authorization"],
        trust_bundle=w["trust_bundle"],
        wire_bytes=WIRE,
        peer_identity_bytes=PEER,
        context=_context(w),
        observed_at=AT,
    )
    assert second.sent is False
    assert len(send.calls) == 1
    assert second.reason_code == EXECUTION_AUTHORIZATION_CONSUMED


def test_missing_authorization_fails_closed(tmp_path):
    w = _world(tmp_path)
    send = _CountingSend()
    result = _dispatcher(w, send).dispatch(
        authorization={},
        trust_bundle=w["trust_bundle"],
        wire_bytes=WIRE,
        peer_identity_bytes=PEER,
        context=_context(w),
        observed_at=AT,
    )
    assert result.sent is False
    assert send.calls == []
    assert result.reason_code is not None


def test_invalid_trust_bundle_fails_closed(tmp_path):
    w = _world(tmp_path)
    send = _CountingSend()
    result = _dispatcher(w, send).dispatch(
        authorization=w["authorization"],
        trust_bundle=None,
        wire_bytes=WIRE,
        peer_identity_bytes=PEER,
        context=_context(w),
        observed_at=AT,
    )
    assert result.sent is False
    assert send.calls == []
    assert result.reason_code == "TRUST_BUNDLE_UNAVAILABLE"


def test_expired_authorization_fails_closed(tmp_path):
    w = _world(tmp_path, expires_at="2026-08-10T12:00:01Z")
    send = _CountingSend()
    result = _dispatcher(w, send).dispatch(
        authorization=w["authorization"],
        trust_bundle=w["trust_bundle"],
        wire_bytes=WIRE,
        peer_identity_bytes=PEER,
        context=_context(w, at_time="2026-08-10T12:00:05Z"),
        observed_at=AT,
    )
    assert result.sent is False
    assert send.calls == []
    assert result.reason_code == "EXECUTION_AUTHORIZATION_NON_CONFORMANT"
    assert not w["store"].is_execution_authorization_consumed(w["ea_id"])
