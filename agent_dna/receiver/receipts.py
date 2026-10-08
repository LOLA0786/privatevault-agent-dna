"""Receiver receipts: signed, hash-chained evidence written by the system of record.

Every request the receiver gate evaluates (admitted or refused) produces one
receipt, signed by a key the *receiver operator* holds. That key is not a
PrivateVault key: ``ReceiverGate`` refuses to start if the receipt key appears
anywhere in the pinned PrivateVault trust bundle. The receipt is therefore
the receiving system's own statement of what reached it, not the
authorizer's statement about itself.

Receipts form a single chain per ledger: ``sequence`` is contiguous from 1
and ``previous_receipt_digest`` is the digest of the prior signed receipt
(the zero digest for sequence 1).

Field values are restricted to ASCII-keyed strings, safe integers, and null
so the canonical form can be reproduced without this package (see
``tools/verify_receiver_receipts.py``).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey

from agent_dna.authority_v01 import (
    CANONICALIZATION,
    AuthorityFormatError,
    sha256_digest,
    sign_document,
    verify_document_signature,
)

RECEIVER_RECEIPT_SPEC = "pv-receiver-receipt/0.1-experimental"
GENESIS_DIGEST = "sha256:" + "0" * 64

OUTCOME_ADMITTED = "ADMITTED"
OUTCOME_REFUSED = "REFUSED"

RECEIPT_FIELDS = frozenset(
    {
        "spec",
        "canonicalization",
        "receiver_id",
        "sequence",
        "previous_receipt_digest",
        "received_at",
        "outcome",
        "reason_code",
        "method",
        "path",
        "wire_bytes_digest",
        "wire_bytes_length",
        "execution_authorization_id",
        "execution_authorization_digest",
        "organisation_id",
        "action_digest",
        "receipt_key_id",
        "signature",
    }
)

_NULLABLE = frozenset(
    {
        "reason_code",
        "execution_authorization_id",
        "execution_authorization_digest",
        "organisation_id",
        "action_digest",
    }
)


def _check_value(field: str, value: Any) -> None:
    if value is None:
        if field not in _NULLABLE:
            raise AuthorityFormatError(f"receiver_receipt.{field}: may not be null")
        return
    if isinstance(value, bool):
        raise AuthorityFormatError(f"receiver_receipt.{field}: boolean not allowed")
    if isinstance(value, int):
        if not 0 <= value <= (1 << 53) - 1:
            raise AuthorityFormatError(
                f"receiver_receipt.{field}: integer out of range"
            )
        return
    if isinstance(value, str):
        return
    raise AuthorityFormatError(f"receiver_receipt.{field}: unsupported value type")


def validate_receiver_receipt(receipt: Any) -> Mapping[str, Any]:
    """Strict shape check. Does not verify the signature."""

    if not isinstance(receipt, Mapping):
        raise AuthorityFormatError("receiver_receipt: expected object")
    if set(receipt) != RECEIPT_FIELDS:
        missing = sorted(RECEIPT_FIELDS - set(receipt))
        extra = sorted(set(receipt) - RECEIPT_FIELDS)
        raise AuthorityFormatError(
            f"receiver_receipt: fields differ (missing={missing}, extra={extra})"
        )
    for field, value in receipt.items():
        _check_value(field, value)
    if receipt["spec"] != RECEIVER_RECEIPT_SPEC:
        raise AuthorityFormatError("receiver_receipt.spec: unsupported spec")
    if receipt["canonicalization"] != CANONICALIZATION:
        raise AuthorityFormatError("receiver_receipt.canonicalization: unsupported")
    if receipt["outcome"] not in {OUTCOME_ADMITTED, OUTCOME_REFUSED}:
        raise AuthorityFormatError("receiver_receipt.outcome: unknown outcome")
    if (receipt["outcome"] == OUTCOME_ADMITTED) != (receipt["reason_code"] is None):
        raise AuthorityFormatError(
            "receiver_receipt: ADMITTED has no reason_code; REFUSED requires one"
        )
    if (
        receipt["outcome"] == OUTCOME_ADMITTED
        and receipt["execution_authorization_id"] is None
    ):
        raise AuthorityFormatError(
            "receiver_receipt: ADMITTED requires an execution_authorization_id"
        )
    if not isinstance(receipt["sequence"], int) or receipt["sequence"] < 1:
        raise AuthorityFormatError("receiver_receipt.sequence: expected integer >= 1")
    return receipt


def sign_receiver_receipt(
    unsigned: Mapping[str, Any], signing_key: SigningKey
) -> dict[str, Any]:
    signed = sign_document(unsigned, signing_key, signature_field="signature")
    validate_receiver_receipt(signed)
    return signed


def receiver_receipt_digest(receipt: Mapping[str, Any]) -> str:
    return sha256_digest(validate_receiver_receipt(receipt))


@dataclass(frozen=True)
class ReceiptChainReport:
    ok: bool
    count: int
    failures: tuple[str, ...]


def verify_receiver_receipt_chain(
    receipts: Iterable[Mapping[str, Any]],
    *,
    receiver_public_keys: Mapping[str, str],
    receiver_id: str,
) -> ReceiptChainReport:
    """Verify signatures, contiguity, and linkage of a full receipt chain.

    ``receiver_public_keys`` maps ``receipt_key_id`` to the base64 Ed25519
    public key the receiver operator published. Supplied out of band; never
    read from the receipts themselves.
    """

    failures: list[str] = []
    previous = GENESIS_DIGEST
    expected_sequence = 1
    count = 0
    for index, receipt in enumerate(receipts):
        count += 1
        where = f"receipt[{index}]"
        try:
            validate_receiver_receipt(receipt)
        except AuthorityFormatError as exc:
            failures.append(f"{where}: {exc}")
            return ReceiptChainReport(False, count, tuple(failures))
        if receipt["receiver_id"] != receiver_id:
            failures.append(f"{where}: receiver_id {receipt['receiver_id']!r} differs")
        if receipt["sequence"] != expected_sequence:
            failures.append(
                f"{where}: sequence {receipt['sequence']} expected {expected_sequence}"
            )
        if receipt["previous_receipt_digest"] != previous:
            failures.append(f"{where}: previous_receipt_digest does not link")
        key = receiver_public_keys.get(str(receipt["receipt_key_id"]))
        if key is None:
            failures.append(f"{where}: receipt_key_id is not a published receiver key")
        else:
            try:
                verify_document_signature(
                    receipt, signature_field="signature", public_key=key
                )
            except (AuthorityFormatError, BadSignatureError):
                failures.append(f"{where}: signature invalid")
        previous = sha256_digest(receipt)
        expected_sequence = int(receipt["sequence"]) + 1
    return ReceiptChainReport(not failures, count, tuple(failures))
