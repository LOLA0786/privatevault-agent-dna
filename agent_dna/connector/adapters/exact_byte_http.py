"""Exact-byte egress dispatcher — sidecar last meter after mint.

Order is fixed and fail-closed:

  1. Freeze the outbound buffer.
  2. Offline-verify the execution authorization against the *pinned*
     trust bundle, destination, wire bytes, and non-peer fields.
     No network connection is opened until this succeeds.
  3. Bind credentials to the allowlisted destination / audience, then
     open a *per-dispatch* TLS session. Peer identity is the DER of the
     authenticated certificate.
  4. Verify the observed TLS peer against the authorization.
  5. Atomically consume the EA (at-most-once). A burned permit is not retried.
  6. Transmit the same ``bytes`` object.
  7. Stamp ``observed_at`` after body transmission. Sign the dispatch witness.
  8. Stamp ``closed_at`` after the HTTP response is observed. Sign closure
     with the observed status. The connection is closed on every path.

This class is an in-process sidecar. It does not provide complete mediation
until deployed as a separately isolated sole-egress service with network
policy that denies the agent any other outbound path.

Outcomes
--------
``NOT_SENT`` / ``CONTROL_FAILURE``
    Transport was never invoked; the permit is not burned.
``EXECUTED``
    Verified sidecar witness and closure exist; ``tool_executed=True``.
``INDETERMINATE``
    Transport invocation began but completion is unverified.
    ``tool_executed=None``, ``retryable=False``. Never auto-retried.

A caller-supplied ``SendFn`` is test-only and does not prove bytes on the
wire. Production uses ``TlsHttpsSidecarTransport``.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from nacl.signing import SigningKey

from agent_dna.authority_v01 import (
    CANONICALIZATION,
    AuthorityFormatError,
    VerificationReport,
    sha256_digest,
)
from agent_dna.authorize_binding import EXECUTION_AUTHORIZATION_CONSUMED
from agent_dna.closure_v01 import CLOSURE_RECORD_SPEC, sign_closure_record
from agent_dna.connector.adapters.execution_trust import validate_execution_trust_bundle
from agent_dna.connector.adapters.sidecar_transport import (
    DISPATCH_CREDENTIAL_MISMATCH,
    CallbackSidecarTransport,
    RecordingSidecarTransport,
    SendFn,
    SidecarResponseError,
    SidecarSendResult,
    SidecarSession,
    SidecarTransport,
    TlsHttpsSidecarTransport,
    require_credential_binding,
)
from agent_dna.dispatch_v01 import create_dispatch_witness, dispatch_witness_digest
from agent_dna.execution_v01 import (
    execution_authorization_digest,
    sha256_bytes_digest,
    verify_execution_authorization,
)
from agent_dna.receiver.permit_header import PERMIT_HEADER, encode_permit_header

DISPATCH_WITNESS_CREATE_FAILED = "DISPATCH_WITNESS_CREATE_FAILED"
DISPATCH_TRANSPORT_REFUSED = "DISPATCH_TRANSPORT_REFUSED"
DISPATCH_WIRE_BYTES_INVALID = "DISPATCH_WIRE_BYTES_INVALID"
DISPATCH_PAYLOAD_INVALID = "DISPATCH_PAYLOAD_INVALID"
CONSUME_LEDGER_UNAVAILABLE = "CONSUME_LEDGER_UNAVAILABLE"
DISPATCH_PERMIT_HEADER_INVALID = "DISPATCH_PERMIT_HEADER_INVALID"
DISPATCH_HANDSHAKE_FAILED = "DISPATCH_HANDSHAKE_FAILED"
DISPATCH_BYTES_MISMATCH = "DISPATCH_BYTES_MISMATCH"
DISPATCH_CALLER_PEER_REFUSED = "DISPATCH_CALLER_PEER_REFUSED"
DISPATCH_CALLER_TRUST_REFUSED = "DISPATCH_CALLER_TRUST_REFUSED"
DISPATCH_CALLER_SEND_REFUSED = "DISPATCH_CALLER_SEND_REFUSED"
DISPATCH_CLOSURE_FAILED = "DISPATCH_CLOSURE_FAILED"
DISPATCH_DESTINATION_MISMATCH = "DISPATCH_DESTINATION_MISMATCH"
DISPATCH_PEER_MISMATCH = "DISPATCH_PEER_MISMATCH"

OUTCOME_NOT_SENT = "NOT_SENT"
OUTCOME_CONTROL_FAILURE = "CONTROL_FAILURE"
OUTCOME_EXECUTED = "EXECUTED"
OUTCOME_INDETERMINATE = "INDETERMINATE"


def serialize_json_payload(payload: Any) -> bytes:
    """Serialize a JSON-compatible payload to the exact bytes that will be sent.

    Matches ``pv-json-parameters/0.1``: sorted keys, compact separators, UTF-8,
    no NaN. Authorize re-derives these bytes from ``action.parameters``.
    """
    try:
        return json.dumps(
            payload,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"payload is not JSON-serializable: {exc}") from exc


@dataclass(frozen=True)
class ExactByteContext:
    """Mint-bound digests and observed action/dispatch for EA verify."""

    request_id: str
    observed_action: Mapping[str, Any]
    observed_dispatch: Mapping[str, Any]
    decision_receipt_digest: str
    authority_receipt_digest: str
    approval_artifact_digest: str
    state_snapshot_digest: str
    policy_bundle_digest: str
    obligations_digest: str
    at_time: str


@dataclass(frozen=True)
class WitnessSigner:
    """Sidecar-owned witness/closure key material (not the EA signer)."""

    signing_key: SigningKey
    signer_key_id: str
    witness_component_id: str
    wire_content_type: str = "application/json"
    wire_content_encoding: str = "identity"
    closure_signer_key_id: str = ""
    closure_signing_key: SigningKey | None = None


@dataclass
class ExactByteDispatchResult:
    outcome: str
    tool_executed: bool | None
    retryable: bool
    sent: bool
    verification: VerificationReport | None = None
    witness: dict[str, Any] | None = None
    closure: dict[str, Any] | None = None
    transport_response: Any = None
    reason_code: str | None = None
    detail: str | None = None
    wire_bytes: bytes | None = None


def _not_sent(
    *,
    reason_code: str,
    detail: str | None = None,
    verification: VerificationReport | None = None,
    wire_bytes: bytes | None = None,
    outcome: str = OUTCOME_CONTROL_FAILURE,
) -> ExactByteDispatchResult:
    return ExactByteDispatchResult(
        outcome=outcome,
        tool_executed=False,
        retryable=False,
        sent=False,
        verification=verification,
        reason_code=reason_code,
        detail=detail,
        wire_bytes=wire_bytes,
    )


def _indeterminate(
    *,
    reason_code: str,
    detail: str | None = None,
    verification: VerificationReport | None = None,
    wire_bytes: bytes | None = None,
) -> ExactByteDispatchResult:
    return ExactByteDispatchResult(
        outcome=OUTCOME_INDETERMINATE,
        tool_executed=None,
        retryable=False,
        sent=False,
        verification=verification,
        reason_code=reason_code,
        detail=detail,
        wire_bytes=wire_bytes,
    )


@dataclass
class ExactByteHttpDispatcher:
    """Fail-closed egress with a pinned trust bundle and sidecar transport.

    At-most-once: ``try_consume_execution_authorization`` claims the id
    before the body is written. If send later fails, the permit is burned
    (INDETERMINATE). Do not retry that authorization.
    """

    consume_ledger: Any
    witness: WitnessSigner
    trust_bundle: Mapping[str, Any]
    transport: SidecarTransport
    # When True, the signed authorization travels with the request in
    # ``X-PV-Execution-Authorization`` so a receiver gate at the system of
    # record can verify and consume it independently (ADR 0019). The header
    # does not change the bound wire bytes.
    attach_permit_header: bool = False
    _test_allow_callback_transport: bool = False

    def __post_init__(self) -> None:
        self.trust_bundle = validate_execution_trust_bundle(self.trust_bundle)
        if (
            isinstance(self.transport, CallbackSidecarTransport)
            and not self._test_allow_callback_transport
        ):
            raise RuntimeError(
                "callback SendFn transport is test-only; production must use "
                "a sidecar-owned transport"
            )

    def dispatch(
        self,
        *,
        authorization: Mapping[str, Any],
        context: ExactByteContext,
        wire_bytes: bytes | bytearray | memoryview | None = None,
        payload: Any | None = None,
        attempt: int = 1,
        dispatch_witness_id: str | None = None,
        observed_at: str | None = None,
        trust_bundle: Any = None,
        peer_identity_bytes: Any = None,
        send: Any = None,
    ) -> ExactByteDispatchResult:
        """Dispatch exact bytes bound by ``authorization``.

        ``trust_bundle``, ``peer_identity_bytes``, and ``send`` are rejected
        if supplied: the caller does not choose the trust root, the TLS peer,
        or the transport.
        """
        if trust_bundle is not None:
            return _not_sent(
                reason_code=DISPATCH_CALLER_TRUST_REFUSED,
                detail="callers cannot select a trust bundle at dispatch time",
                outcome=OUTCOME_CONTROL_FAILURE,
            )
        if peer_identity_bytes is not None:
            return _not_sent(
                reason_code=DISPATCH_CALLER_PEER_REFUSED,
                detail="callers cannot supply peer_identity_bytes; "
                "the sidecar derives peer identity from TLS",
                outcome=OUTCOME_CONTROL_FAILURE,
            )
        if send is not None:
            return _not_sent(
                reason_code=DISPATCH_CALLER_SEND_REFUSED,
                detail="callers cannot supply a send callback at dispatch time",
                outcome=OUTCOME_CONTROL_FAILURE,
            )
        frozen = self._freeze_wire(wire_bytes=wire_bytes, payload=payload)
        if isinstance(frozen, ExactByteDispatchResult):
            return frozen
        del observed_at
        return self._dispatch_frozen(
            authorization=authorization,
            context=context,
            wire=frozen,
            attempt=attempt,
            dispatch_witness_id=dispatch_witness_id,
        )

    def _dispatch_frozen(
        self,
        *,
        authorization: Mapping[str, Any],
        context: ExactByteContext,
        wire: bytes,
        attempt: int,
        dispatch_witness_id: str | None,
    ) -> ExactByteDispatchResult:
        destination, operation, audience, dest_fail = self._sealed_destination(
            authorization, context
        )
        if dest_fail is not None:
            dest_fail.wire_bytes = wire
            return dest_fail
        offline = self._verify_pinned(
            authorization=authorization,
            context=context,
            wire=wire,
            peer=b"",
            check_peer_identity=False,
        )
        if not offline.ok:
            return _not_sent(
                reason_code=offline.reason_code
                or "EXECUTION_AUTHORIZATION_NON_CONFORMANT",
                detail="; ".join(offline.failures) if offline.failures else None,
                verification=offline,
                wire_bytes=wire,
            )
        try:
            require_credential_binding(
                destination=destination,
                credential_audience=audience,
                allowed_destinations=frozenset(
                    getattr(self.transport, "allowed_destinations", ()) or ()
                ),
                allowed_audiences=frozenset(
                    getattr(self.transport, "allowed_audiences", ()) or ()
                ),
                has_credentials=bool(
                    getattr(self.transport, "credentials_headers", {}) or {}
                ),
            )
        except RuntimeError as exc:
            return _not_sent(
                reason_code=DISPATCH_CREDENTIAL_MISMATCH,
                detail=str(exc),
                verification=offline,
                wire_bytes=wire,
            )
        session: SidecarSession | None = None
        try:
            session = self.transport.connect(destination, credential_audience=audience)
            return self._after_handshake(
                authorization=authorization,
                context=context,
                wire=wire,
                session=session,
                operation=operation,
                attempt=attempt,
                dispatch_witness_id=dispatch_witness_id,
            )
        except SidecarResponseError as exc:
            return _indeterminate(
                reason_code=DISPATCH_TRANSPORT_REFUSED,
                detail=f"{type(exc).__name__}: {exc}",
                verification=offline,
                wire_bytes=wire,
            )
        except Exception as exc:
            if session is None:
                return _not_sent(
                    reason_code=DISPATCH_HANDSHAKE_FAILED,
                    detail=f"{type(exc).__name__}: {exc}",
                    verification=offline,
                    wire_bytes=wire,
                )
            return _indeterminate(
                reason_code=DISPATCH_TRANSPORT_REFUSED,
                detail=f"{type(exc).__name__}: {exc}",
                verification=offline,
                wire_bytes=wire,
            )
        finally:
            if session is not None:
                session.close()

    def _after_handshake(
        self,
        *,
        authorization: Mapping[str, Any],
        context: ExactByteContext,
        wire: bytes,
        session: SidecarSession,
        operation: str,
        attempt: int,
        dispatch_witness_id: str | None,
    ) -> ExactByteDispatchResult:
        peer = bytes(session.peer_identity_bytes)
        report = self._verify_pinned(
            authorization=authorization,
            context=context,
            wire=wire,
            peer=peer,
            check_peer_identity=True,
        )
        if not report.ok:
            return _not_sent(
                reason_code=report.reason_code or DISPATCH_PEER_MISMATCH,
                detail="; ".join(report.failures) if report.failures else None,
                verification=report,
                wire_bytes=wire,
            )
        ids = self._authorization_ids(authorization, report, wire)
        if isinstance(ids, ExactByteDispatchResult):
            return ids
        ea_id, organisation_id = ids
        extra_headers: dict[str, str] | None = None
        if self.attach_permit_header:
            try:
                extra_headers = {PERMIT_HEADER: encode_permit_header(authorization)}
            except (AuthorityFormatError, TypeError, ValueError) as exc:
                return _not_sent(
                    reason_code=DISPATCH_PERMIT_HEADER_INVALID,
                    detail=str(exc),
                    verification=report,
                    wire_bytes=wire,
                )
        consume_at = _rfc3339_now()
        consumed = self._consume(ea_id, organisation_id, consume_at, report, wire)
        if consumed is not None:
            return consumed
        return self._transmit_and_attest(
            authorization=authorization,
            context=context,
            wire=wire,
            peer=peer,
            operation=operation,
            report=report,
            attempt=attempt,
            dispatch_witness_id=dispatch_witness_id,
            session=session,
            extra_headers=extra_headers,
        )

    def _sealed_destination(
        self,
        authorization: Mapping[str, Any],
        context: ExactByteContext,
    ) -> tuple[str, str, str, ExactByteDispatchResult | None]:
        sealed = authorization.get("dispatch")
        observed = context.observed_dispatch
        if not isinstance(sealed, Mapping) or not isinstance(observed, Mapping):
            return (
                "",
                "",
                "",
                _not_sent(
                    reason_code=DISPATCH_DESTINATION_MISMATCH,
                    detail="dispatch destination missing from authorization or context",
                ),
            )
        sealed_dest = sealed.get("destination")
        observed_dest = observed.get("destination")
        if (
            not isinstance(sealed_dest, str)
            or not sealed_dest
            or sealed_dest != observed_dest
        ):
            return (
                "",
                "",
                "",
                _not_sent(
                    reason_code=DISPATCH_DESTINATION_MISMATCH,
                    detail="caller destination does not match sealed dispatch",
                ),
            )
        operation = sealed.get("operation")
        if not isinstance(operation, str) or not operation:
            return (
                "",
                "",
                "",
                _not_sent(
                    reason_code=DISPATCH_DESTINATION_MISMATCH,
                    detail="sealed dispatch operation missing",
                ),
            )
        audience = sealed.get("credential_audience")
        if not isinstance(audience, str):
            audience = ""
        return sealed_dest, operation, audience, None

    def _verify_pinned(
        self,
        *,
        authorization: Mapping[str, Any],
        context: ExactByteContext,
        wire: bytes,
        peer: bytes,
        check_peer_identity: bool = True,
    ) -> VerificationReport:
        return verify_execution_authorization(
            authorization,
            self.trust_bundle,
            expected_request_id=context.request_id,
            expected_action=dict(context.observed_action),
            expected_dispatch=dict(context.observed_dispatch),
            expected_decision_receipt_digest=context.decision_receipt_digest,
            expected_authority_receipt_digest=context.authority_receipt_digest,
            expected_approval_artifact_digest=context.approval_artifact_digest,
            expected_state_snapshot_digest=context.state_snapshot_digest,
            expected_policy_bundle_digest=context.policy_bundle_digest,
            expected_obligations_digest=context.obligations_digest,
            expected_wire_bytes=wire,
            expected_peer_identity_bytes=peer,
            at_time=context.at_time,
            already_consumed=False,
            consume_ledger=None,
            check_peer_identity=check_peer_identity,
        )

    def _authorization_ids(
        self,
        authorization: Mapping[str, Any],
        report: VerificationReport,
        wire: bytes,
    ) -> tuple[str, str] | ExactByteDispatchResult:
        ea_id = authorization.get("execution_authorization_id")
        organisation_id = authorization.get("organisation_id")
        if not isinstance(ea_id, str) or not ea_id:
            return _not_sent(
                reason_code="SCHEMA_INVALID",
                detail="execution_authorization_id missing after verify",
                verification=report,
                wire_bytes=wire,
            )
        if not isinstance(organisation_id, str) or not organisation_id:
            return _not_sent(
                reason_code="SCHEMA_INVALID",
                detail="organisation_id missing after verify",
                verification=report,
                wire_bytes=wire,
            )
        return ea_id, organisation_id

    def _consume(
        self,
        ea_id: str,
        organisation_id: str,
        consumed_at: str,
        report: VerificationReport,
        wire: bytes,
    ) -> ExactByteDispatchResult | None:
        try:
            claimed = self.consume_ledger.try_consume_execution_authorization(
                ea_id,
                organisation_id=organisation_id,
                consumed_at=consumed_at,
            )
        except Exception as exc:
            return _not_sent(
                reason_code=CONSUME_LEDGER_UNAVAILABLE,
                detail=f"{type(exc).__name__}: {exc}",
                verification=report,
                wire_bytes=wire,
            )
        if not claimed:
            return _not_sent(
                reason_code=EXECUTION_AUTHORIZATION_CONSUMED,
                detail="execution authorization has already been consumed",
                verification=report,
                wire_bytes=wire,
            )
        return None

    def _transmit_and_attest(
        self,
        *,
        authorization: Mapping[str, Any],
        context: ExactByteContext,
        wire: bytes,
        peer: bytes,
        operation: str,
        report: VerificationReport,
        attempt: int,
        dispatch_witness_id: str | None,
        session: SidecarSession,
        extra_headers: Mapping[str, str] | None = None,
    ) -> ExactByteDispatchResult:
        try:
            if extra_headers:
                sent = session.write(
                    wire, operation=operation, extra_headers=extra_headers
                )
            else:
                sent = session.write(wire, operation=operation)
        except SidecarResponseError as exc:
            return _indeterminate(
                reason_code=DISPATCH_TRANSPORT_REFUSED,
                detail=f"{type(exc).__name__}: {exc}",
                verification=report,
                wire_bytes=wire,
            )
        except Exception as exc:
            return _indeterminate(
                reason_code=DISPATCH_TRANSPORT_REFUSED,
                detail=f"{type(exc).__name__}: {exc}",
                verification=report,
                wire_bytes=wire,
            )
        observed_at = _rfc3339_now()
        if not isinstance(sent, SidecarSendResult) or not sent.send_began:
            return _indeterminate(
                reason_code=DISPATCH_TRANSPORT_REFUSED,
                detail="sidecar did not confirm send began",
                verification=report,
                wire_bytes=wire,
            )
        if sent.bytes_committed != wire:
            return _indeterminate(
                reason_code=DISPATCH_BYTES_MISMATCH,
                detail="sidecar committed different bytes than the frozen buffer",
                verification=report,
                wire_bytes=wire,
            )
        if sent.peer_identity_bytes != peer:
            return _indeterminate(
                reason_code=DISPATCH_BYTES_MISMATCH,
                detail="TLS peer identity changed between handshake and write",
                verification=report,
                wire_bytes=wire,
            )
        closed_at = _rfc3339_now()
        if closed_at < observed_at:
            closed_at = observed_at
        return self._attest_after_send(
            authorization=authorization,
            context=context,
            wire=wire,
            sent=sent,
            report=report,
            attempt=attempt,
            dispatch_witness_id=dispatch_witness_id,
            observed_at=observed_at,
            closed_at=closed_at,
        )

    def _attest_after_send(
        self,
        *,
        authorization: Mapping[str, Any],
        context: ExactByteContext,
        wire: bytes,
        sent: SidecarSendResult,
        report: VerificationReport,
        attempt: int,
        dispatch_witness_id: str | None,
        observed_at: str,
        closed_at: str,
    ) -> ExactByteDispatchResult:
        meta_id = dispatch_witness_id or f"dw-{uuid.uuid4()}"
        try:
            witness = create_dispatch_witness(
                {
                    "dispatch_witness_id": meta_id,
                    "observed_at": observed_at,
                    "attempt": attempt,
                    "witness_component_id": self.witness.witness_component_id,
                    "wire_content_type": self.witness.wire_content_type,
                    "wire_content_encoding": self.witness.wire_content_encoding,
                    "signer_key_id": self.witness.signer_key_id,
                },
                authorization=authorization,
                trust_bundle=self.trust_bundle,
                observed_action=dict(context.observed_action),
                observed_dispatch=dict(context.observed_dispatch),
                wire_bytes=sent.bytes_committed,
                peer_identity_bytes=sent.peer_identity_bytes,
                signing_key=self.witness.signing_key,
            )
        except (AuthorityFormatError, TypeError, ValueError) as exc:
            return _indeterminate(
                reason_code=DISPATCH_WITNESS_CREATE_FAILED,
                detail=str(exc),
                verification=report,
                wire_bytes=wire,
            )
        try:
            closure = self._sign_closure(
                authorization=authorization,
                witness=witness,
                sent=sent,
                closed_at=closed_at,
            )
        except (AuthorityFormatError, TypeError, ValueError) as exc:
            return _indeterminate(
                reason_code=DISPATCH_CLOSURE_FAILED,
                detail=str(exc),
                verification=report,
                wire_bytes=wire,
            )
        return ExactByteDispatchResult(
            outcome=OUTCOME_EXECUTED,
            tool_executed=True,
            retryable=False,
            sent=True,
            verification=report,
            witness=witness,
            closure=closure,
            transport_response=sent.response_body,
            wire_bytes=wire,
        )

    def _sign_closure(
        self,
        *,
        authorization: Mapping[str, Any],
        witness: Mapping[str, Any],
        sent: SidecarSendResult,
        closed_at: str,
    ) -> dict[str, Any]:
        closure_key = self.witness.closure_signing_key
        closure_key_id = self.witness.closure_signer_key_id
        if closure_key is None or not closure_key_id:
            raise ValueError(
                "closure_signing_key and closure_signer_key_id are required; "
                "witness-key fallback is forbidden"
            )
        status = int(sent.http_status)
        outcome = _http_dispatch_outcome(status)
        if outcome == "TRANSPORT_ERROR":
            response_status: str | None = None
            response_digest: str | None = None
            response_length: int | None = None
            effect_state = "UNKNOWN"
        else:
            body = sent.response_body
            response_status = str(status)
            response_digest = sha256_bytes_digest(body)
            response_length = len(body)
            effect_state = "UNCONFIRMED"
        unsigned = {
            "spec": CLOSURE_RECORD_SPEC,
            "canonicalization": CANONICALIZATION,
            "closure_id": f"cl-{uuid.uuid4()}",
            "organisation_id": authorization["organisation_id"],
            "request_id": authorization["request_id"],
            "execution_authorization_id": authorization["execution_authorization_id"],
            "execution_authorization_digest": execution_authorization_digest(
                authorization
            ),
            "dispatch_witness_id": witness["dispatch_witness_id"],
            "dispatch_witness_digest": dispatch_witness_digest(witness),
            "closed_at": closed_at,
            "closure_component_id": self.witness.witness_component_id,
            "dispatch_outcome": outcome,
            "response_status": response_status,
            "response_bytes_digest": response_digest,
            "response_bytes_length": response_length,
            "effect_state": effect_state,
            "effect_evidence_digest": None,
            "idempotency_key_digest": authorization["dispatch"][
                "idempotency_key_digest"
            ],
            "authorization_use_count": 1,
            "trust_bundle_digest": sha256_digest(self.trust_bundle),
            "signer_key_id": closure_key_id,
        }
        return sign_closure_record(unsigned, closure_key)

    def _freeze_wire(
        self,
        *,
        wire_bytes: bytes | bytearray | memoryview | None,
        payload: Any | None,
    ) -> bytes | ExactByteDispatchResult:
        if wire_bytes is not None and payload is not None:
            return _not_sent(
                reason_code=DISPATCH_PAYLOAD_INVALID,
                detail="provide wire_bytes or payload, not both",
            )
        if wire_bytes is not None:
            try:
                return bytes(wire_bytes)
            except (TypeError, ValueError) as exc:
                return _not_sent(
                    reason_code=DISPATCH_WIRE_BYTES_INVALID,
                    detail=str(exc),
                )
        if payload is not None:
            try:
                return serialize_json_payload(payload)
            except ValueError as exc:
                return _not_sent(
                    reason_code=DISPATCH_PAYLOAD_INVALID,
                    detail=str(exc),
                )
        return _not_sent(
            reason_code=DISPATCH_PAYLOAD_INVALID,
            detail="wire_bytes or payload is required",
        )


def recording_send(sink: list[bytes]) -> SendFn:
    """Test-only callback. Does not prove bytes reached a peer."""

    def _send(wire: bytes, _dispatch: Mapping[str, Any]) -> dict[str, Any]:
        sink.append(wire)
        return {"status": "recorded", "length": len(wire)}

    return _send


def httpx_send(
    *,
    url: str,
    method: str = "POST",
    headers: Mapping[str, str] | None = None,
    timeout: float = 10.0,
) -> SendFn:
    """Test-only HTTP callback. Production must use TlsHttpsSidecarTransport."""

    def _send(wire: bytes, _dispatch: Mapping[str, Any]) -> Any:
        import httpx

        with httpx.Client(timeout=timeout) as client:
            response = client.request(
                method,
                url,
                content=wire,
                headers=dict(headers or {}),
            )
            response.raise_for_status()
            return response

    return _send


def _http_dispatch_outcome(status: int) -> str:
    if 200 <= status <= 299:
        return "ACKNOWLEDGED"
    if 400 <= status <= 499:
        return "REJECTED"
    return "TRANSPORT_ERROR"


def _rfc3339_now() -> str:
    stamp = datetime.now(UTC).isoformat(timespec="microseconds")
    return stamp.replace("+00:00", "Z")


# Re-export transports so callers import one module.
__all__ = [
    "CallbackSidecarTransport",
    "DISPATCH_BYTES_MISMATCH",
    "DISPATCH_CALLER_PEER_REFUSED",
    "DISPATCH_CALLER_SEND_REFUSED",
    "DISPATCH_CALLER_TRUST_REFUSED",
    "DISPATCH_CREDENTIAL_MISMATCH",
    "DISPATCH_HANDSHAKE_FAILED",
    "DISPATCH_PEER_MISMATCH",
    "ExactByteContext",
    "ExactByteDispatchResult",
    "ExactByteHttpDispatcher",
    "OUTCOME_CONTROL_FAILURE",
    "OUTCOME_EXECUTED",
    "OUTCOME_INDETERMINATE",
    "OUTCOME_NOT_SENT",
    "RecordingSidecarTransport",
    "TlsHttpsSidecarTransport",
    "WitnessSigner",
    "httpx_send",
    "recording_send",
    "serialize_json_payload",
]
