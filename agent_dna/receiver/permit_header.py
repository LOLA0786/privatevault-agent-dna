"""Strict wire codec for carrying an execution authorization to the receiver.

The permit travels in one HTTP header, ``X-PV-Execution-Authorization``.
Its value is unpadded base64url of the RFC 8785 canonical JSON of the signed
authorization. Decoding is strict and has exactly one accepted encoding per
permit:

- one header occurrence only (ambiguity refuses);
- bounded length;
- base64url alphabet only, no padding, no whitespace;
- strict JSON (no duplicate keys, no non-finite numbers);
- the decoded bytes must already be canonical. A permit re-serialized with
  different whitespace or key order is refused rather than normalized, so the
  receiver never accepts two byte forms of one authorization.

Decoding proves nothing about the signature. ``ReceiverGate`` verifies it.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping
from typing import Any

from agent_dna.authority_v01 import (
    AuthorityFormatError,
    canonicalize,
    strict_json_loads,
)

PERMIT_HEADER = "X-PV-Execution-Authorization"
PERMIT_HEADER_LOWER = PERMIT_HEADER.lower()
MAX_PERMIT_HEADER_CHARS = 16_384

_B64URL_RE = re.compile(r"[A-Za-z0-9_-]+\Z")


def encode_permit_header(authorization: Mapping[str, Any]) -> str:
    """Encode a signed authorization as the receiver header value."""

    raw = canonicalize(authorization)
    value = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    if len(value) > MAX_PERMIT_HEADER_CHARS:
        raise AuthorityFormatError(
            f"permit header exceeds {MAX_PERMIT_HEADER_CHARS} characters"
        )
    return value


def decode_permit_header(value: Any) -> dict[str, Any]:
    """Decode one header value into the authorization object, or refuse."""

    if isinstance(value, bytes):
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError as exc:
            raise AuthorityFormatError("permit header is not ASCII") from exc
    if not isinstance(value, str) or not value:
        raise AuthorityFormatError("permit header is empty")
    if len(value) > MAX_PERMIT_HEADER_CHARS:
        raise AuthorityFormatError(
            f"permit header exceeds {MAX_PERMIT_HEADER_CHARS} characters"
        )
    if not _B64URL_RE.fullmatch(value):
        raise AuthorityFormatError("permit header is not unpadded base64url")
    padded = value + "=" * (-len(value) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, binascii.Error) as exc:
        raise AuthorityFormatError("permit header is not valid base64url") from exc
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != value:
        raise AuthorityFormatError("permit header base64url is not canonical")
    decoded = strict_json_loads(raw)
    if not isinstance(decoded, dict):
        raise AuthorityFormatError("permit header does not carry a JSON object")
    if canonicalize(decoded) != raw:
        raise AuthorityFormatError("permit header JSON is not RFC 8785 canonical")
    return decoded
