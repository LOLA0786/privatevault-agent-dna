"""Reference exact-byte HTTP / tool egress adapter.

Closes the library-side last meter after mint. Order is fixed:

  1. Serialize / freeze the exact outbound payload bytes.
  2. Recompute the wire digest via ``verify_execution_authorization``
     (no consume yet) — refuse on any mismatch, expiry, or bad signature.
  3. Create a ``dispatch_witness`` over those same bytes (dispatch_v01).
  4. Atomically consume the EA via the durable ledger.
  5. Only then call ``send`` with that same ``bytes`` object.

Nothing is sent if any step before send fails. Integrators who bypass
this adapter are outside this guarantee (see docs/WHAT-WE-DO-NOT-CLAIM.md).
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from nacl.signing import SigningKey

from agent_dna.authority_v01 import AuthorityFormatError, VerificationReport
from agent_dna.authorize_binding import EXECUTION_AUTHORIZATION_CONSUMED
from agent_dna.dispatch_v01 import create_dispatch_witness
from agent_dna.execution_v01 import verify_execution_authorization

DISPATCH_WITNESS_CREATE_FAILED = "DISPATCH_WITNESS_CREATE_FAILED"
DISPATCH_TRANSPORT_REFUSED = "DISPATCH_TRANSPORT_REFUSED"
DISPATCH_WIRE_BYTES_INVALID = "DISPATCH_WIRE_BYTES_INVALID"
DISPATCH_PAYLOAD_INVALID = "DISPATCH_PAYLOAD_INVALID"
CONSUME_LEDGER_UNAVAILABLE = "CONSUME_LEDGER_UNAVAILABLE"

SendFn = Callable[[bytes, Mapping[str, Any]], Any]


def serialize_json_payload(payload: Any) -> bytes:
    """Serialize a JSON-compatible payload to the exact bytes that will be sent.

    Compact separators — the EA must have been minted against these bytes.
    """
    try:
        return json.dumps(
            payload,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
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
    """Independent egress witness key material (not the EA signer)."""

    signing_key: SigningKey
    signer_key_id: str
    witness_component_id: str
    wire_content_type: str = "application/json"
    wire_content_encoding: str = "identity"


@dataclass
class ExactByteDispatchResult:
    sent: bool
    verification: VerificationReport | None = None
    witness: dict[str, Any] | None = None
    transport_response: Any = None
    reason_code: str | None = None
    detail: str | None = None
    wire_bytes: bytes | None = None


@dataclass
class ExactByteHttpDispatcher:
    """Fail-closed egress: verify → witness → consume → send exact bytes."""

    consume_ledger: Any
    witness: WitnessSigner
    send: SendFn

    def dispatch(  # noqa: C901 — ordered fail-closed checklist
        self,
        *,
        authorization: Mapping[str, Any],
        trust_bundle: Mapping[str, Any] | None,
        peer_identity_bytes: bytes | bytearray | memoryview,
        context: ExactByteContext,
        wire_bytes: bytes | bytearray | memoryview | None = None,
        payload: Any | None = None,
        attempt: int = 1,
        dispatch_witness_id: str | None = None,
        observed_at: str | None = None,
    ) -> ExactByteDispatchResult:
        """Dispatch exact bytes bound by ``authorization``.

        Provide either ``wire_bytes`` (already serialized) or ``payload``
        (JSON-serialized here). The transport receives the identical buffer.
        """
        frozen = self._freeze_wire(wire_bytes=wire_bytes, payload=payload)
        if isinstance(frozen, ExactByteDispatchResult):
            return frozen
        wire = frozen

        try:
            peer = bytes(peer_identity_bytes)
        except (TypeError, ValueError) as exc:
            return ExactByteDispatchResult(
                sent=False,
                reason_code=DISPATCH_WIRE_BYTES_INVALID,
                detail=str(exc),
                wire_bytes=wire,
            )

        # 2. Recompute digests / check signature / expiry — do not consume yet.
        report = verify_execution_authorization(
            authorization,
            trust_bundle,
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
        )
        if not report.ok:
            return ExactByteDispatchResult(
                sent=False,
                verification=report,
                reason_code=report.reason_code,
                detail="; ".join(report.failures) if report.failures else None,
                wire_bytes=wire,
            )
        if trust_bundle is None:
            return ExactByteDispatchResult(
                sent=False,
                verification=report,
                reason_code="TRUST_BUNDLE_UNAVAILABLE",
                detail="no out-of-band trust bundle was supplied",
                wire_bytes=wire,
            )

        ea_id = authorization.get("execution_authorization_id")
        organisation_id = authorization.get("organisation_id")
        if not isinstance(ea_id, str) or not ea_id:
            return ExactByteDispatchResult(
                sent=False,
                verification=report,
                reason_code="SCHEMA_INVALID",
                detail="execution_authorization_id missing after verify",
                wire_bytes=wire,
            )
        if not isinstance(organisation_id, str) or not organisation_id:
            return ExactByteDispatchResult(
                sent=False,
                verification=report,
                reason_code="SCHEMA_INVALID",
                detail="organisation_id missing after verify",
                wire_bytes=wire,
            )

        # 3. Witness over the frozen buffer (independent signer).
        meta_observed_at = observed_at or _rfc3339_now()
        meta_id = dispatch_witness_id or f"dw-{uuid.uuid4()}"
        try:
            witness = create_dispatch_witness(
                {
                    "dispatch_witness_id": meta_id,
                    "observed_at": meta_observed_at,
                    "attempt": attempt,
                    "witness_component_id": self.witness.witness_component_id,
                    "wire_content_type": self.witness.wire_content_type,
                    "wire_content_encoding": self.witness.wire_content_encoding,
                    "signer_key_id": self.witness.signer_key_id,
                },
                authorization=authorization,
                trust_bundle=trust_bundle,
                observed_action=dict(context.observed_action),
                observed_dispatch=dict(context.observed_dispatch),
                wire_bytes=wire,
                peer_identity_bytes=peer,
                signing_key=self.witness.signing_key,
            )
        except (AuthorityFormatError, TypeError, ValueError) as exc:
            return ExactByteDispatchResult(
                sent=False,
                verification=report,
                reason_code=DISPATCH_WITNESS_CREATE_FAILED,
                detail=str(exc),
                wire_bytes=wire,
            )

        # 4. Atomic single-use consume — never send if already claimed.
        try:
            claimed = self.consume_ledger.try_consume_execution_authorization(
                ea_id,
                organisation_id=organisation_id,
                consumed_at=meta_observed_at,
            )
        except Exception as exc:
            return ExactByteDispatchResult(
                sent=False,
                verification=report,
                witness=witness,
                reason_code=CONSUME_LEDGER_UNAVAILABLE,
                detail=f"{type(exc).__name__}: {exc}",
                wire_bytes=wire,
            )
        if not claimed:
            return ExactByteDispatchResult(
                sent=False,
                verification=report,
                witness=witness,
                reason_code=EXECUTION_AUTHORIZATION_CONSUMED,
                detail="execution authorization has already been consumed",
                wire_bytes=wire,
            )

        # 5. Send the identical buffer — never a re-serialize.
        try:
            response = self.send(wire, context.observed_dispatch)
        except Exception as exc:
            return ExactByteDispatchResult(
                sent=False,
                verification=report,
                witness=witness,
                reason_code=DISPATCH_TRANSPORT_REFUSED,
                detail=f"{type(exc).__name__}: {exc}",
                wire_bytes=wire,
            )

        return ExactByteDispatchResult(
            sent=True,
            verification=report,
            witness=witness,
            transport_response=response,
            wire_bytes=wire,
        )

    def _freeze_wire(
        self,
        *,
        wire_bytes: bytes | bytearray | memoryview | None,
        payload: Any | None,
    ) -> bytes | ExactByteDispatchResult:
        if wire_bytes is not None and payload is not None:
            return ExactByteDispatchResult(
                sent=False,
                reason_code=DISPATCH_PAYLOAD_INVALID,
                detail="provide wire_bytes or payload, not both",
            )
        if wire_bytes is not None:
            try:
                return bytes(wire_bytes)
            except (TypeError, ValueError) as exc:
                return ExactByteDispatchResult(
                    sent=False,
                    reason_code=DISPATCH_WIRE_BYTES_INVALID,
                    detail=str(exc),
                )
        if payload is not None:
            try:
                return serialize_json_payload(payload)
            except ValueError as exc:
                return ExactByteDispatchResult(
                    sent=False,
                    reason_code=DISPATCH_PAYLOAD_INVALID,
                    detail=str(exc),
                )
        return ExactByteDispatchResult(
            sent=False,
            reason_code=DISPATCH_PAYLOAD_INVALID,
            detail="wire_bytes or payload is required",
        )


def recording_send(sink: list[bytes]) -> SendFn:
    """Test/demo transport that records the exact buffer and does not network."""

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
    """Optional real HTTP transport: POSTs the frozen wire bytes as the body."""

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


def _rfc3339_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
