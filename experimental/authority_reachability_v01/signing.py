"""Hash and Ed25519 signature envelope for reachability reports."""

from __future__ import annotations

import base64
import binascii
import hashlib
from collections.abc import Mapping
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from agent_dna.authority_v01 import canonicalize

from .model import (
    SIGNED_REPORT_SPEC,
    GraphFormatError,
    require_exact_fields,
)


def sign_analysis_report(
    report: Mapping[str, Any],
    signing_key: SigningKey,
    *,
    signer_key_id: str,
) -> dict[str, Any]:
    """Return a signed envelope over the exact deterministic report."""

    report_bytes = canonicalize(dict(report))
    digest = (
        "sha256:"
        + hashlib.sha256(report_bytes).hexdigest()
    )

    unsigned = {
        "spec": SIGNED_REPORT_SPEC,
        "report": dict(report),
        "report_hash": digest,
        "signer_key_id": signer_key_id,
    }

    signature = signing_key.sign(
        canonicalize(unsigned)
    ).signature

    return {
        **unsigned,
        "signature": (
            "ed25519:"
            + base64.b64encode(signature).decode("ascii")
        ),
    }


def verify_signed_analysis_report(
    envelope: Mapping[str, Any],
    *,
    trusted_keys: Mapping[str, str],
) -> bool:
    """Verify the report hash and signature against an out-of-band key map."""

    require_exact_fields(
        envelope,
        required={
            "spec",
            "report",
            "report_hash",
            "signer_key_id",
            "signature",
        },
        path="signed_report",
    )

    if envelope["spec"] != SIGNED_REPORT_SPEC:
        raise GraphFormatError(
            "signed_report.spec: unsupported spec"
        )

    key_id = envelope["signer_key_id"]
    if (
        not isinstance(key_id, str)
        or key_id not in trusted_keys
    ):
        raise GraphFormatError(
            "signed_report.signer_key_id: untrusted key"
        )

    report = envelope["report"]
    if not isinstance(report, Mapping):
        raise GraphFormatError(
            "signed_report.report: expected object"
        )

    expected_hash = (
        "sha256:"
        + hashlib.sha256(
            canonicalize(report)
        ).hexdigest()
    )

    if envelope["report_hash"] != expected_hash:
        return False

    signature_text = envelope["signature"]
    if (
        not isinstance(signature_text, str)
        or not signature_text.startswith("ed25519:")
    ):
        raise GraphFormatError(
            "signed_report.signature: malformed signature"
        )

    try:
        signature = base64.b64decode(
            signature_text.removeprefix("ed25519:"),
            validate=True,
        )
    except (ValueError, binascii.Error):
        return False

    if len(signature) != 64:
        return False

    try:
        public_key = base64.b64decode(
            trusted_keys[key_id],
            validate=True,
        )
        verifier = VerifyKey(public_key)
    except (ValueError, binascii.Error) as exc:
        raise GraphFormatError(
            "signed_report: malformed trusted public key"
        ) from exc

    unsigned = {
        key: value
        for key, value in envelope.items()
        if key != "signature"
    }

    try:
        verifier.verify(
            canonicalize(unsigned),
            signature,
        )
    except (BadSignatureError, ValueError):
        return False

    return True
