"""Receiver gate: enforcement at the system of record, not at the agent.

The exact-byte sidecar verifies and consumes a permit *before it sends*. That
control lives on the agent's side of the wire. An agent (or anything else)
that holds the system's credentials and calls the API directly never meets
it; `docs/WHAT-WE-DO-NOT-CLAIM.md` says so.

``ReceiverGate`` runs on the receiving side, operated by the owner of the
system of record (a core-banking API, a payment rail). It admits a state-
changing request only if the request itself carries a PrivateVault execution
authorization that verifies offline against a pinned trust bundle *and*
binds what actually arrived:

1. signature by an ``execution_authorization_signer`` key in the pinned
   bundle, and the bundle digest the permit names;
2. this receiver as ``dispatch.credential_audience`` and one of its
   configured ``dispatch.destination`` values (a permit for another system
   is refused here);
3. the received ``METHOD path`` equals ``dispatch.operation`` exactly;
4. ``not_before <= received_at < expires_at`` (optional bounded skew);
5. SHA-256 and length of the received body equal the permit's wire digest;
6. the received body equals ``action.parameters`` under the permit's named
   serialization (the signed business fields — payee, amount — are the
   bytes that arrived);
7. operator-owned local checks (may only refuse, never admit);
8. a durable, receiver-owned single-use claim.

Presenter (ADR 0022): a spec 0.2 permit names the TLS client key that may
present it. The gate then requires the request to have arrived over mTLS
with that key, checked right after the signature and before anything else
(a wrong presenter never reaches the ledger, so the permit is not burned).
With ``require_presenter`` the gate refuses permits that name no presenter.

Every evaluated request yields a signed, hash-chained receiver receipt, so
refusals are evidence too. Any internal error refuses (fail closed).

What this does not do: it protects only operations routed through a gate.
Coverage of a bank's APIs is a deployment property. See ADR 0019.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey

from agent_dna.authority_v01 import (
    CANONICALIZATION,
    AuthorityFormatError,
    _parse_timestamp,
    encode_public_key,
    sha256_digest,
    validate_trust_bundle,
    verify_document_signature,
)
from agent_dna.execution_v01 import (
    bound_presenter_digest,
    validate_execution_authorization,
)
from agent_dna.key_custody import Ed25519Signer
from agent_dna.presenter_identity import (
    PresenterIdentityError,
    presenter_identity_digest,
)
from agent_dna.receiver.ledger import CLAIM_DUPLICATE_TRANSACTION, ReceiverLedger
from agent_dna.receiver.permit_header import PERMIT_HEADER_LOWER, decode_permit_header
from agent_dna.receiver.receipts import (
    OUTCOME_ADMITTED,
    OUTCOME_REFUSED,
    RECEIVER_RECEIPT_SPEC,
    sign_receiver_receipt,
)
from agent_dna.receiver.transactions import (
    TransactionKeyError,
    extract_transaction_key,
    transaction_reference,
    validate_field_path,
)
from agent_dna.revocation_list import (
    RECEIVER_REVOCATION_LIST_STALE,
)
from agent_dna.wire_serialization_v01 import serialize_parameters_wire

RECEIVER_PERMIT_MISSING = "RECEIVER_PERMIT_MISSING"
RECEIVER_PERMIT_AMBIGUOUS = "RECEIVER_PERMIT_AMBIGUOUS"
RECEIVER_PERMIT_MALFORMED = "RECEIVER_PERMIT_MALFORMED"
RECEIVER_PERMIT_SCHEMA_INVALID = "RECEIVER_PERMIT_SCHEMA_INVALID"
RECEIVER_ORGANISATION_MISMATCH = "RECEIVER_ORGANISATION_MISMATCH"
RECEIVER_TRUST_ROOT_UNKNOWN = "RECEIVER_TRUST_ROOT_UNKNOWN"
RECEIVER_KEY_USAGE_INVALID = "RECEIVER_KEY_USAGE_INVALID"
RECEIVER_PERMIT_SIGNATURE_INVALID = "RECEIVER_PERMIT_SIGNATURE_INVALID"
RECEIVER_TRUST_BUNDLE_MISMATCH = "RECEIVER_TRUST_BUNDLE_MISMATCH"
RECEIVER_TRANSPORT_UNSUPPORTED = "RECEIVER_TRANSPORT_UNSUPPORTED"
RECEIVER_AUDIENCE_MISMATCH = "RECEIVER_AUDIENCE_MISMATCH"
RECEIVER_DESTINATION_MISMATCH = "RECEIVER_DESTINATION_MISMATCH"
RECEIVER_OPERATION_MISMATCH = "RECEIVER_OPERATION_MISMATCH"
RECEIVER_PERMIT_NOT_YET_VALID = "RECEIVER_PERMIT_NOT_YET_VALID"
RECEIVER_PERMIT_EXPIRED = "RECEIVER_PERMIT_EXPIRED"
RECEIVER_WIRE_MISMATCH = "RECEIVER_WIRE_MISMATCH"
RECEIVER_WIRE_ACTION_MISMATCH = "RECEIVER_WIRE_ACTION_MISMATCH"
RECEIVER_LOCAL_POLICY_REFUSED = "RECEIVER_LOCAL_POLICY_REFUSED"
RECEIVER_PERMIT_CONSUMED = "RECEIVER_PERMIT_CONSUMED"
RECEIVER_BODY_TOO_LARGE = "RECEIVER_BODY_TOO_LARGE"
RECEIVER_CONTENT_ENCODING_REFUSED = "RECEIVER_CONTENT_ENCODING_REFUSED"
RECEIVER_WIRE_HEADER_MISMATCH = "RECEIVER_WIRE_HEADER_MISMATCH"
RECEIVER_INTERNAL_ERROR = "RECEIVER_INTERNAL_ERROR"
RECEIVER_LEDGER_UNAVAILABLE = "RECEIVER_LEDGER_UNAVAILABLE"
# Presenter binding (ADR 0022)
RECEIVER_PRESENTER_REQUIRED = "RECEIVER_PRESENTER_REQUIRED"
RECEIVER_PRESENTER_MISSING = "RECEIVER_PRESENTER_MISSING"
RECEIVER_PRESENTER_MISMATCH = "RECEIVER_PRESENTER_MISMATCH"
# ADR 0030: business transaction keys.
RECEIVER_TRANSACTION_KEY_INVALID = "RECEIVER_TRANSACTION_KEY_INVALID"
RECEIVER_DUPLICATE_TRANSACTION = "RECEIVER_DUPLICATE_TRANSACTION"

_ENUMERATED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"})
_READ_ONLY_METHODS = frozenset({"GET", "HEAD"})

# Headers that make common frameworks and proxies act on a method or URL
# other than the one on the request line. The permit binds METHOD + path,
# so a request carrying any of these is asking the upstream to do
# something the permit did not authorise.
_OVERRIDE_HEADERS = frozenset(
    {
        "x-http-method-override",
        "x-http-method",
        "x-method-override",
        "x-original-url",
        "x-original-method",
        "x-rewrite-url",
    }
)

# A local check sees the verified action and dispatch and returns ``None`` to
# pass or a short refusal detail. It can only add refusals.
LocalCheck = Callable[[Mapping[str, Any], Mapping[str, Any]], str | None]


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _rfc3339(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _split_operation(operation: str) -> tuple[str, str] | None:
    parts = operation.strip().split(None, 1)
    if len(parts) != 2:
        return None
    method, path = parts[0].upper(), parts[1]
    if method not in _ENUMERATED_METHODS or not path.startswith("/"):
        return None
    return method, path


@dataclass(frozen=True)
class ReceiverDecision:
    """Outcome of one evaluation. ``receipt`` is None only on ledger failure
    or for an operator-declared unprotected read."""

    admitted: bool
    reason_code: str | None
    detail: str | None
    http_status: int
    receipt: Mapping[str, Any] | None
    authorization: Mapping[str, Any] | None = None
    # ADR 0030: the business transaction this admission claimed, if the
    # operation declares a key: (operation, key).
    transaction: tuple[str, str] | None = None

    @property
    def transaction_reference(self) -> str | None:
        """Opaque upstream ``Idempotency-Key`` for the claimed transaction."""
        if self.transaction is None or self.authorization is None:
            return None
        return transaction_reference(
            self.authorization["organisation_id"], *self.transaction
        )


class _RefusalError(Exception):
    def __init__(
        self,
        reason_code: str,
        detail: str,
        http_status: int = 403,
        ea: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(detail)
        self.reason_code = reason_code
        self.detail = detail
        self.http_status = http_status
        self.ea = ea


@dataclass
class ReceiverGate:
    """Verify-then-admit gate for one receiving system.

    ``receiver_id`` must equal the permit's ``dispatch.credential_audience``.
    ``destinations`` are the ``dispatch.destination`` values that name this
    system. ``trust_bundle`` is the PrivateVault bundle the operator pinned
    out of band. ``receipt_signing_key`` belongs to the receiver operator.
    """

    receiver_id: str
    destinations: frozenset[str]
    trust_bundle: Mapping[str, Any]
    ledger: ReceiverLedger
    receipt_signing_key: SigningKey | Ed25519Signer
    receipt_key_id: str
    unprotected_operations: frozenset[str] = field(default_factory=frozenset)
    local_checks: Sequence[LocalCheck] = ()
    max_body_bytes: int = 1_048_576
    clock_skew: timedelta = timedelta(0)
    # Optional RevocationListCache (agent_dna.revocation_list). When set,
    # listed or suspended permits are refused, and a missing or expired
    # list refuses everything (fail closed).
    revocations: Any = None
    # Refuse permits that do not bind a presenter (spec 0.1). A permit that
    # does bind one is always checked, whatever this is set to.
    require_presenter: bool = False
    # ADR 0030: "METHOD PATH" -> dotted JSON field in the request body that
    # identifies the business transaction (an invoice number). Each key is
    # admitted once; see agent_dna/receiver/transactions.py.
    transaction_keys: Mapping[str, str] = field(default_factory=dict)
    _keys: dict[str, Mapping[str, Any]] = field(init=False, repr=False)
    _bundle_digest: str = field(init=False, repr=False)
    _unprotected: frozenset[tuple[str, str]] = field(init=False, repr=False)

    def __post_init__(self) -> None:  # noqa: C901 - ordered config refusals
        if not isinstance(self.receiver_id, str) or not self.receiver_id:
            raise ValueError("receiver_id is required")
        if not self.destinations or not all(
            isinstance(d, str) and d for d in self.destinations
        ):
            raise ValueError("at least one receiver destination is required")
        self._keys = validate_trust_bundle(self.trust_bundle)
        if not any(
            "execution_authorization_signer" in key["usages"]
            for key in self._keys.values()
        ):
            raise ValueError(
                "pinned trust bundle has no execution_authorization_signer key"
            )
        receipt_public = encode_public_key(self.receipt_signing_key)
        if any(key["public_key"] == receipt_public for key in self._keys.values()):
            raise ValueError(
                "receipt signing key appears in the PrivateVault trust bundle; "
                "the receiver must attest with an independent key"
            )
        if not isinstance(self.receipt_key_id, str) or not self.receipt_key_id:
            raise ValueError("receipt_key_id is required")
        if self.max_body_bytes < 0:
            raise ValueError("max_body_bytes must be >= 0")
        if self.clock_skew < timedelta(0) or self.clock_skew > timedelta(seconds=30):
            raise ValueError("clock_skew must be between 0 and 30 seconds")
        unprotected: set[tuple[str, str]] = set()
        for operation in self.unprotected_operations:
            split = _split_operation(operation)
            if split is None:
                raise ValueError(
                    f"unprotected operation is not METHOD PATH: {operation!r}"
                )
            if split[0] not in _READ_ONLY_METHODS:
                raise ValueError(
                    f"only GET/HEAD may be unprotected; refused {operation!r}"
                )
            unprotected.add(split)
        self._unprotected = frozenset(unprotected)
        for operation, field_path in self.transaction_keys.items():
            split = _split_operation(operation)
            if split is None:
                raise ValueError(
                    f"transaction key operation is not METHOD PATH: {operation!r}"
                )
            if split[0] in _READ_ONLY_METHODS:
                raise ValueError(
                    f"a read cannot carry a transaction key: {operation!r}"
                )
            validate_field_path(field_path)
        self._bundle_digest = sha256_digest(self.trust_bundle)

    @property
    def receipt_public_key(self) -> str:
        return encode_public_key(self.receipt_signing_key)

    # ------------------------------------------------------------------ check

    def check(
        self,
        *,
        method: str,
        path: str,
        headers: Iterable[tuple[str, str]] | Mapping[str, str],
        body: bytes,
        received_at: datetime | None = None,
        presenter_certificate: bytes | None = None,
    ) -> ReceiverDecision:
        """Evaluate one received request. Never raises.

        ``presenter_certificate``: DER of the TLS client certificate the
        request arrived with, as authenticated by the server's TLS layer;
        None when there was no client certificate."""

        now = received_at or datetime.now(UTC)
        # HTTP methods are case-sensitive and are forwarded as received, so
        # never normalise: a "post" admitted against a POST permit would be
        # forwarded as "post" while the receipt says "POST".
        method = method or ""
        body = bytes(body)
        if (method, path) in self._unprotected and not body:
            return ReceiverDecision(
                True, None, "operator-declared unprotected read", 200, None
            )

        ea: Mapping[str, Any] | None = None
        transaction: tuple[str, str] | None = None
        try:
            ea = self._verify(method, path, headers, body, now, presenter_certificate)
            transaction = self._transaction(ea, body)
        except _RefusalError as refusal:
            return self._refuse(refusal, method, path, body, now, ea_hint=refusal.ea)
        except Exception as exc:  # fail closed on anything unexpected
            return self._refuse(
                _RefusalError(RECEIVER_INTERNAL_ERROR, type(exc).__name__, 500),
                method,
                path,
                body,
                now,
                ea_hint=None,
            )
        return self._admit(ea, method, path, body, now, transaction)

    def record_outcome(
        self,
        decision: ReceiverDecision,
        upstream_status: int | None,
        *,
        at: datetime | None = None,
    ) -> str | None:
        """Record the upstream's answer to an admitted request (ADR 0030).

        ``upstream_status`` is the HTTP status, or None when the upstream
        failed or did not answer. Returns the transaction's new state, or
        None when the admission claimed no transaction key. Never raises: a
        failure to record leaves the claim CLAIMED, which blocks the key
        until it is reconciled (the safe direction)."""
        if not decision.admitted or decision.transaction is None:
            return None
        ea = decision.authorization
        if ea is None:
            return None
        try:
            return self.ledger.record_outcome(
                ea["organisation_id"],
                ea["execution_authorization_id"],
                upstream_status,
                at=_rfc3339(at or datetime.now(UTC)),
            )
        except Exception:
            return None

    def _transaction(
        self, ea: Mapping[str, Any], body: bytes
    ) -> tuple[str, str] | None:
        operation = ea["dispatch"]["operation"]
        field_path = self.transaction_keys.get(operation)
        if field_path is None:
            return None
        try:
            key = extract_transaction_key(body, field_path)
        except TransactionKeyError as exc:
            raise _RefusalError(
                RECEIVER_TRANSACTION_KEY_INVALID, str(exc), 400, ea=ea
            ) from None
        return operation, key

    def refuse_unread_body(
        self, *, method: str, path: str, received_at: datetime | None = None
    ) -> ReceiverDecision:
        """Refuse a request whose body exceeded the bound before it was read.

        The body is not retained, so the receipt records the empty digest.
        """
        return self._refuse(
            _RefusalError(RECEIVER_BODY_TOO_LARGE, "request body exceeds bound", 413),
            (method or "").upper(),
            path,
            b"",
            received_at or datetime.now(UTC),
            ea_hint=None,
        )

    # ---------------------------------------------------------------- verify

    def _verify(
        self,
        method: str,
        path: str,
        headers: Iterable[tuple[str, str]] | Mapping[str, str],
        body: bytes,
        now: datetime,
        presenter_certificate: bytes | None = None,
    ) -> Mapping[str, Any]:
        """Ordered checklist; each step refuses with its own reason code."""
        if len(body) > self.max_body_bytes:
            raise _RefusalError(
                RECEIVER_BODY_TOO_LARGE, "request body exceeds bound", 413
            )
        ea = self._permit_from_headers(headers)
        self._verify_trust(ea)
        self._verify_presenter(ea, presenter_certificate)
        self._verify_destination(ea, method, path)
        self._verify_time(ea, now)
        self._verify_not_revoked(ea, now)
        self._verify_body(ea, body)
        self._verify_headers(ea, headers)
        self._run_local_checks(ea)
        return ea

    @staticmethod
    def _permit_from_headers(
        headers: Iterable[tuple[str, str]] | Mapping[str, str],
    ) -> Mapping[str, Any]:
        pairs = list(headers.items()) if isinstance(headers, Mapping) else list(headers)
        lowered = [(str(k).lower(), v) for k, v in pairs]
        encodings = [v for k, v in lowered if k == "content-encoding"]
        if any(str(v).strip().lower() not in {"", "identity"} for v in encodings):
            raise _RefusalError(
                RECEIVER_CONTENT_ENCODING_REFUSED,
                "body must arrive unencoded so its bytes can be bound",
            )
        permits = [v for k, v in lowered if k == PERMIT_HEADER_LOWER]
        if not permits:
            raise _RefusalError(
                RECEIVER_PERMIT_MISSING, "no execution authorization presented"
            )
        if len(permits) > 1:
            raise _RefusalError(
                RECEIVER_PERMIT_AMBIGUOUS, "more than one permit header"
            )
        try:
            decoded = decode_permit_header(permits[0])
        except AuthorityFormatError as exc:
            raise _RefusalError(RECEIVER_PERMIT_MALFORMED, str(exc)) from exc
        try:
            return validate_execution_authorization(decoded)
        except (AuthorityFormatError, TypeError, ValueError) as exc:
            raise _RefusalError(RECEIVER_PERMIT_SCHEMA_INVALID, str(exc)) from exc

    def _verify_presenter(
        self, ea: Mapping[str, Any], certificate: bytes | None
    ) -> None:
        bound = bound_presenter_digest(ea)
        if bound is None:
            if self.require_presenter:
                raise _RefusalError(
                    RECEIVER_PRESENTER_REQUIRED,
                    "this receiver requires permits that bind a presenter",
                    ea=ea,
                )
            return
        if not certificate:
            raise _RefusalError(
                RECEIVER_PRESENTER_MISSING,
                "permit binds a presenter; request carried no TLS client certificate",
                ea=ea,
            )
        try:
            presented = presenter_identity_digest(certificate)
        except PresenterIdentityError as exc:
            raise _RefusalError(RECEIVER_PRESENTER_MISMATCH, str(exc), ea=ea) from exc
        if presented != bound:
            raise _RefusalError(
                RECEIVER_PRESENTER_MISMATCH,
                "TLS client key is not the presenter this permit names",
                ea=ea,
            )

    def _verify_trust(self, ea: Mapping[str, Any]) -> None:
        if ea["organisation_id"] != self.trust_bundle["organisation_id"]:
            raise _RefusalError(
                RECEIVER_ORGANISATION_MISMATCH, "permit organisation differs", ea=ea
            )
        key = self._keys.get(ea["signer_key_id"])
        if key is None:
            raise _RefusalError(
                RECEIVER_TRUST_ROOT_UNKNOWN, "signer key not in pinned bundle", ea=ea
            )
        if "execution_authorization_signer" not in key["usages"]:
            raise _RefusalError(
                RECEIVER_KEY_USAGE_INVALID, "signer key lacks permit usage", ea=ea
            )
        try:
            verify_document_signature(
                ea, signature_field="signature", public_key=key["public_key"]
            )
        except (AuthorityFormatError, BadSignatureError) as exc:
            raise _RefusalError(
                RECEIVER_PERMIT_SIGNATURE_INVALID, "signature invalid", ea=ea
            ) from exc
        if ea["trust_bundle_digest"] != self._bundle_digest:
            raise _RefusalError(
                RECEIVER_TRUST_BUNDLE_MISMATCH, "permit names another bundle", ea=ea
            )

    def _verify_destination(
        self, ea: Mapping[str, Any], method: str, path: str
    ) -> None:
        dispatch = ea["dispatch"]
        if dispatch["transport"] != "https":
            raise _RefusalError(
                RECEIVER_TRANSPORT_UNSUPPORTED, "only https permits are admitted", ea=ea
            )
        if dispatch["credential_audience"] != self.receiver_id:
            raise _RefusalError(
                RECEIVER_AUDIENCE_MISMATCH, "permit audience is another system", ea=ea
            )
        if dispatch["destination"] not in self.destinations:
            raise _RefusalError(
                RECEIVER_DESTINATION_MISMATCH,
                "permit destination is another system",
                ea=ea,
            )
        bound = _split_operation(dispatch["operation"])
        if bound is None or bound != (method, path):
            raise _RefusalError(
                RECEIVER_OPERATION_MISMATCH, "received METHOD path not bound", ea=ea
            )

    def _verify_not_revoked(self, ea: Mapping[str, Any], now: datetime) -> None:
        if self.revocations is None:
            return
        hit = self.revocations.refusal(ea, now=now, clock_skew=self.clock_skew)
        if hit is not None:
            code, detail = hit
            status = 503 if code == RECEIVER_REVOCATION_LIST_STALE else 403
            raise _RefusalError(code, detail, status, ea=ea)

    def _verify_time(self, ea: Mapping[str, Any], now: datetime) -> None:
        not_before = _parse_timestamp(ea["not_before"], "not_before")
        expires_at = _parse_timestamp(ea["expires_at"], "expires_at")
        if now + self.clock_skew < not_before:
            raise _RefusalError(
                RECEIVER_PERMIT_NOT_YET_VALID, "permit not yet valid", ea=ea
            )
        if now - self.clock_skew >= expires_at:
            raise _RefusalError(RECEIVER_PERMIT_EXPIRED, "permit expired", ea=ea)

    @staticmethod
    def _verify_body(ea: Mapping[str, Any], body: bytes) -> None:
        if (
            _sha256_bytes(body) != ea["expected_wire_bytes_digest"]
            or len(body) != ea["expected_wire_bytes_length"]
        ):
            raise _RefusalError(
                RECEIVER_WIRE_MISMATCH, "received body is not the bound bytes", ea=ea
            )
        try:
            expected_wire = serialize_parameters_wire(
                ea["action"]["parameters"],
                serialization=ea["dispatch"]["serialization"],
                path="action.parameters",
            )
        except AuthorityFormatError as exc:
            raise _RefusalError(RECEIVER_WIRE_ACTION_MISMATCH, str(exc), ea=ea) from exc
        if expected_wire != body:
            raise _RefusalError(
                RECEIVER_WIRE_ACTION_MISMATCH,
                "received body is not the signed action parameters",
                ea=ea,
            )

    @staticmethod
    def _verify_headers(
        ea: Mapping[str, Any],
        headers: Iterable[tuple[str, str]] | Mapping[str, str],
    ) -> None:
        """Bind the headers that change how the upstream reads the bytes."""
        pairs = list(headers.items()) if isinstance(headers, Mapping) else list(headers)
        lowered = [(str(k).lower(), str(v)) for k, v in pairs]
        dispatch = ea["dispatch"]
        overrides = sorted({k for k, _ in lowered if k in _OVERRIDE_HEADERS})
        if overrides:
            raise _RefusalError(
                RECEIVER_WIRE_HEADER_MISMATCH,
                f"method/URL override header(s) not bound by permit: {overrides}",
                ea=ea,
            )
        if str(dispatch.get("wire_content_encoding", "identity")).lower() != (
            "identity"
        ):
            raise _RefusalError(
                RECEIVER_CONTENT_ENCODING_REFUSED,
                "permit binds an encoded body; only identity is admitted",
                ea=ea,
            )
        content_types = [v for k, v in lowered if k == "content-type"]
        if len(content_types) > 1:
            raise _RefusalError(
                RECEIVER_WIRE_HEADER_MISMATCH, "more than one Content-Type", ea=ea
            )
        bound = str(dispatch.get("wire_content_type") or "").split(";")[0]
        if content_types and bound:
            received = content_types[0].split(";")[0]
            if received.strip().lower() != bound.strip().lower():
                raise _RefusalError(
                    RECEIVER_WIRE_HEADER_MISMATCH,
                    f"Content-Type {received.strip()!r} is not the bound "
                    f"{bound.strip()!r}",
                    ea=ea,
                )

    def _run_local_checks(self, ea: Mapping[str, Any]) -> None:
        for check in self.local_checks:
            try:
                detail = check(ea["action"], ea["dispatch"])
            except Exception as exc:
                detail = f"local check raised {type(exc).__name__}"
            if detail is not None:
                raise _RefusalError(RECEIVER_LOCAL_POLICY_REFUSED, str(detail), ea=ea)

    # --------------------------------------------------------------- receipts

    def _unsigned(
        self,
        *,
        sequence: int,
        previous: str,
        now: datetime,
        outcome: str,
        reason_code: str | None,
        method: str,
        path: str,
        body: bytes,
        ea: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        return {
            "spec": RECEIVER_RECEIPT_SPEC,
            "canonicalization": CANONICALIZATION,
            "receiver_id": self.receiver_id,
            "sequence": sequence,
            "previous_receipt_digest": previous,
            "received_at": _rfc3339(now),
            "outcome": outcome,
            "reason_code": reason_code,
            "method": method[:16] or "?",
            "path": path[:2048] or "?",
            "wire_bytes_digest": _sha256_bytes(body),
            "wire_bytes_length": len(body),
            "execution_authorization_id": None
            if ea is None
            else ea["execution_authorization_id"],
            "execution_authorization_digest": None if ea is None else sha256_digest(ea),
            "organisation_id": None if ea is None else ea["organisation_id"],
            "action_digest": None if ea is None else ea["action_digest"],
            "receipt_key_id": self.receipt_key_id,
        }

    def _refuse(
        self,
        refusal: _RefusalError,
        method: str,
        path: str,
        body: bytes,
        now: datetime,
        *,
        ea_hint: Mapping[str, Any] | None,
    ) -> ReceiverDecision:
        def make(
            _claimed: bool | str | None, sequence: int, previous: str
        ) -> dict[str, Any]:
            return sign_receiver_receipt(
                self._unsigned(
                    sequence=sequence,
                    previous=previous,
                    now=now,
                    outcome=OUTCOME_REFUSED,
                    reason_code=refusal.reason_code,
                    method=method,
                    path=path,
                    body=body,
                    ea=ea_hint,
                ),
                self.receipt_signing_key,
            )

        try:
            _, receipt = self.ledger.record(claim=None, make_receipt=make)
        except Exception as exc:
            return ReceiverDecision(
                False,
                refusal.reason_code,
                f"{refusal.detail}; receipt not recorded ({type(exc).__name__})",
                refusal.http_status,
                None,
                ea_hint,
            )
        return ReceiverDecision(
            False,
            refusal.reason_code,
            refusal.detail,
            refusal.http_status,
            receipt,
            ea_hint,
        )

    def _admit(
        self,
        ea: Mapping[str, Any],
        method: str,
        path: str,
        body: bytes,
        now: datetime,
        transaction: tuple[str, str] | None = None,
    ) -> ReceiverDecision:
        def make(
            claimed: bool | str | None, sequence: int, previous: str
        ) -> dict[str, Any]:
            admitted = claimed is True
            refusal = (
                RECEIVER_DUPLICATE_TRANSACTION
                if claimed == CLAIM_DUPLICATE_TRANSACTION
                else RECEIVER_PERMIT_CONSUMED
            )
            return sign_receiver_receipt(
                self._unsigned(
                    sequence=sequence,
                    previous=previous,
                    now=now,
                    outcome=OUTCOME_ADMITTED if admitted else OUTCOME_REFUSED,
                    reason_code=None if admitted else refusal,
                    method=method,
                    path=path,
                    body=body,
                    ea=ea,
                ),
                self.receipt_signing_key,
            )

        try:
            claimed, receipt = self.ledger.record(
                claim=(
                    ea["organisation_id"],
                    ea["execution_authorization_id"],
                    _rfc3339(now),
                ),
                make_receipt=make,
                transaction=transaction,
            )
        except Exception as exc:
            return ReceiverDecision(
                False,
                RECEIVER_LEDGER_UNAVAILABLE,
                f"durable claim failed: {type(exc).__name__}",
                503,
                None,
                ea,
            )
        if claimed == CLAIM_DUPLICATE_TRANSACTION:
            return ReceiverDecision(
                False,
                RECEIVER_DUPLICATE_TRANSACTION,
                "this business transaction was already admitted under another "
                "permit; it is refused until reconciled as not executed",
                409,
                receipt,
                ea,
                transaction,
            )
        if claimed is not True:
            return ReceiverDecision(
                False,
                RECEIVER_PERMIT_CONSUMED,
                "permit already admitted by this receiver",
                409,
                receipt,
                ea,
            )
        return ReceiverDecision(True, None, None, 200, receipt, ea, transaction)
