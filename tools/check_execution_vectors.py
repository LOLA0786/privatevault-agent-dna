#!/usr/bin/env python3
"""Check the execution-v01 vectors with a second, independent implementation.

Standard library only: nothing here comes from PrivateVault, PyNaCl or
cryptography. RFC 8785 canonicalization, Ed25519 verification (RFC 8032),
the DER walk to a certificate's SubjectPublicKeyInfo and the four checks the
vectors cover are written from spec/execution-v01/vectors/README.md and the
published standards. Each computed outcome is compared with the one the file
records: evidence state, conformance and reason code, or admission and
reason code. Failure wording is not compared; the README leaves it to each
implementation.

When every case agrees, two implementations that share no code reach the
same decisions, which is the evidence that the format can be implemented
from its text.

    python3 tools/check_execution_vectors.py [path/to/execution-v01.json]
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

DEFAULT_VECTORS = (
    Path(__file__).resolve().parents[1]
    / "spec"
    / "execution-v01"
    / "vectors"
    / "execution-v01.json"
)

PERMIT_V01 = "pv-execution-authorization/0.1-experimental"
PERMIT_V02 = "pv-execution-authorization/0.2-experimental"
WITNESS_SPEC = "pv-dispatch-witness/0.1-experimental"
TRUST_SPEC = "pv-trust-bundle/0.1-experimental"
CANONICALIZATION = "RFC8785"
SERIALIZATION = "pv-json-parameters/0.1"


class FormError(Exception):
    """A document that does not have the required form."""


# ---------------------------------------------------------------- RFC 8785


def jcs(value: Any) -> bytes:
    """RFC 8785 bytes for the JSON values these vectors use (no floats)."""
    return _jcs(value).encode("utf-8")


def _jcs(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise FormError("floats are outside these vectors")
    if isinstance(value, str):
        # RFC 8785 string form: escape only the quote, the backslash and
        # control characters (short forms, else \u00xx), everything else as
        # UTF-8. Python's json module emits exactly that with ensure_ascii off.
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(_jcs(item) for item in value) + "]"
    if isinstance(value, dict):
        keys = sorted(
            value, key=lambda key: key.encode("utf-16-be")
        )  # UTF-16 code-unit order
        return (
            "{"
            + ",".join(
                json.dumps(key, ensure_ascii=False) + ":" + _jcs(value[key])
                for key in keys
            )
            + "}"
        )
    raise FormError(f"not a JSON value: {type(value).__name__}")


def sha256_of_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def digest_of(value: Any) -> str:
    return sha256_of_bytes(jcs(value))


# ---------------------------------------------------------------- RFC 8032

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    if x & 1 != sign:
        x = _P - x
    return x


def _add(
    p: tuple[int, int, int, int], q: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    """Extended-coordinate addition on edwards25519 (RFC 8032, 5.1.4)."""
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _multiply(
    scalar: int, point: tuple[int, int, int, int]
) -> tuple[int, int, int, int]:
    result = (0, 1, 1, 0)
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _same_point(p: tuple[int, int, int, int], q: tuple[int, int, int, int]) -> bool:
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (
        p[1] * q[2] - q[1] * p[2]
    ) % _P == 0


def _decompress(encoded: bytes) -> tuple[int, int, int, int] | None:
    if len(encoded) != 32:
        return None
    y = int.from_bytes(encoded, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


_BASE_Y = 4 * pow(5, _P - 2, _P) % _P
_BASE = (_recover_x(_BASE_Y, 0), _BASE_Y, 1, _recover_x(_BASE_Y, 0) * _BASE_Y % _P)


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """RFC 8032, 5.1.7: accept iff [S]B = R + [k]A."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a, r = _decompress(public_key), _decompress(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None or s >= _L:
        return False
    k = (
        int.from_bytes(
            hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
        )
        % _L
    )
    return _same_point(_multiply(s, _BASE), _add(r, _multiply(k, a)))


# ---------------------------------------------------------------- forms

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_SIGNATURE = re.compile(r"ed25519:[A-Za-z0-9+/]{86}==")
_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z")

ACTION_FIELDS = {
    "subject_principal",
    "subject_key_id",
    "action",
    "resource",
    "parameters",
}
DISPATCH_FIELDS = {
    "transport", "destination", "operation", "wire_content_type", "wire_content_encoding", "tool_id",
    "tool_schema_digest", "tool_artifact_digest", "credential_audience", "idempotency_key_digest",
    "retry_policy_digest", "serialization",
}  # fmt: skip
PERMIT_FIELDS = {
    "spec", "canonicalization", "execution_authorization_id", "organisation_id", "request_id", "issued_at",
    "not_before", "expires_at", "nonce", "decision_receipt_digest", "authority_receipt_digest",
    "approval_artifact_digest", "action", "action_digest", "expected_wire_bytes_digest",
    "expected_wire_bytes_length", "expected_peer_identity_digest", "dispatch", "state_snapshot_digest",
    "policy_bundle_digest", "trust_bundle_digest", "obligations_digest", "max_uses", "signer_key_id", "signature",
}  # fmt: skip
WITNESS_FIELDS = {
    "spec", "canonicalization", "dispatch_witness_id", "organisation_id", "request_id",
    "execution_authorization_id", "execution_authorization_digest", "observed_at", "attempt",
    "witness_component_id", "observed_action_digest", "observed_dispatch", "wire_content_type",
    "wire_content_encoding", "wire_bytes_digest", "wire_bytes_length", "peer_identity_digest",
    "trust_bundle_digest", "signer_key_id", "signature",
}  # fmt: skip
BINDINGS = (
    "decision_receipt_digest", "authority_receipt_digest", "approval_artifact_digest",
    "state_snapshot_digest", "policy_bundle_digest", "obligations_digest",
)  # fmt: skip


def _object(value: Any, fields: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FormError("expected an object")
    if fields is not None and set(value) != fields:
        raise FormError(
            f"fields differ: missing {sorted(fields - set(value))}, extra {sorted(set(value) - fields)}"
        )
    return value


def _text(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise FormError("expected a non-empty string")
    return value


def _digest(value: Any) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise FormError("expected sha256:<64 lowercase hex>")
    return value


def _count(value: Any, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise FormError(f"expected an integer >= {minimum}")
    return value


def _time(value: Any) -> datetime:
    if not isinstance(value, str) or not _TIME.fullmatch(value):
        raise FormError("expected an RFC 3339 UTC timestamp")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _bytes(text: Any) -> bytes:
    try:
        return base64.b64decode(str(text).encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise FormError("not base64") from exc


def check_action_form(action: Any) -> None:
    _object(action, ACTION_FIELDS)
    for field in ("subject_principal", "subject_key_id", "action", "resource"):
        _text(action[field])
    jcs(_object(action["parameters"]))


def check_dispatch_form(dispatch: Any) -> None:
    _object(dispatch, DISPATCH_FIELDS)
    for field in (
        "transport",
        "destination",
        "operation",
        "wire_content_type",
        "wire_content_encoding",
        "tool_id",
        "credential_audience",
    ):
        _text(dispatch[field])
    for field in (
        "tool_schema_digest",
        "tool_artifact_digest",
        "idempotency_key_digest",
        "retry_policy_digest",
    ):
        _digest(dispatch[field])
    if dispatch["serialization"] != SERIALIZATION:
        raise FormError("unknown wire serialization")


def check_permit_form(permit: Any) -> None:  # noqa: C901
    _object(permit)
    fields = {
        PERMIT_V01: PERMIT_FIELDS,
        PERMIT_V02: PERMIT_FIELDS | {"expected_presenter_identity_digest"},
    }.get(permit.get("spec"))
    if fields is None:
        raise FormError("unknown permit spec")
    _object(permit, fields)
    if permit["canonicalization"] != CANONICALIZATION:
        raise FormError("unknown canonicalization")
    for field in (
        "execution_authorization_id",
        "organisation_id",
        "request_id",
        "signer_key_id",
    ):
        _text(permit[field])
    issued, not_before, expires = (
        _time(permit[f]) for f in ("issued_at", "not_before", "expires_at")
    )
    if issued > not_before or not_before >= expires:
        raise FormError("validity window out of order")
    if not 16 <= len(_text(permit["nonce"])) <= 256:
        raise FormError("nonce length")
    for field in (
        "action_digest",
        "expected_wire_bytes_digest",
        "expected_peer_identity_digest",
        "trust_bundle_digest",
        *BINDINGS,
    ):
        if not (field == "approval_artifact_digest" and permit[field] is None):
            _digest(permit[field])
    if permit["spec"] == PERMIT_V02:
        _digest(permit["expected_presenter_identity_digest"])
    check_action_form(permit["action"])
    if permit["action_digest"] != digest_of(permit["action"]):
        raise FormError("action_digest does not match action")
    check_dispatch_form(permit["dispatch"])
    _count(permit["expected_wire_bytes_length"])
    if type(permit["max_uses"]) is not int or permit["max_uses"] != 1:
        raise FormError("max_uses must be exactly 1")
    if not isinstance(permit["signature"], str) or not _SIGNATURE.fullmatch(
        permit["signature"]
    ):
        raise FormError("malformed signature")


def check_witness_form(witness: Any) -> None:
    _object(witness, WITNESS_FIELDS)
    if (
        witness["spec"] != WITNESS_SPEC
        or witness["canonicalization"] != CANONICALIZATION
    ):
        raise FormError("unknown witness spec or canonicalization")
    for field in (
        "dispatch_witness_id", "organisation_id", "request_id", "execution_authorization_id",
        "witness_component_id", "wire_content_type", "wire_content_encoding", "signer_key_id",
    ):  # fmt: skip
        _text(witness[field])
    _time(witness["observed_at"])
    _count(witness["attempt"], 1)
    for field in (
        "execution_authorization_digest",
        "observed_action_digest",
        "wire_bytes_digest",
        "peer_identity_digest",
        "trust_bundle_digest",
    ):
        _digest(witness[field])
    check_dispatch_form(witness["observed_dispatch"])
    for field in ("wire_content_type", "wire_content_encoding"):
        if witness[field] != witness["observed_dispatch"][field]:
            raise FormError(f"{field} differs from observed_dispatch")
    _count(witness["wire_bytes_length"])
    if not isinstance(witness["signature"], str) or not _SIGNATURE.fullmatch(
        witness["signature"]
    ):
        raise FormError("malformed signature")


def trust_keys(bundle: Any) -> dict[str, dict[str, Any]]:
    _object(
        bundle,
        {
            "spec",
            "canonicalization",
            "organisation_id",
            "bundle_version",
            "pinned_at",
            "keys",
        },
    )
    if bundle["spec"] != TRUST_SPEC or bundle["canonicalization"] != CANONICALIZATION:
        raise FormError("unknown trust bundle spec or canonicalization")
    _text(bundle["organisation_id"])
    _count(bundle["bundle_version"], 1)
    _time(bundle["pinned_at"])
    if not isinstance(bundle["keys"], list) or not bundle["keys"]:
        raise FormError("a trust bundle needs keys")
    keys: dict[str, dict[str, Any]] = {}
    for key in bundle["keys"]:
        _object(key, {"key_id", "principal", "algorithm", "public_key", "usages"})
        if key["algorithm"] != "ed25519" or len(_bytes(key["public_key"])) != 32:
            raise FormError("keys must be 32-byte Ed25519 public keys")
        if (
            not isinstance(key["usages"], list)
            or not key["usages"]
            or not all(isinstance(u, str) for u in key["usages"])
        ):
            raise FormError("usages must be a non-empty list of strings")
        if _text(key["key_id"]) in keys:
            raise FormError("duplicate key_id")
        _text(key["principal"])
        keys[key["key_id"]] = key
    return keys


def signature_holds(document: dict[str, Any], public_key: str) -> bool:
    signature = document.get("signature")
    if not isinstance(signature, str) or not _SIGNATURE.fullmatch(signature):
        return False
    unsigned = {
        field: value for field, value in document.items() if field != "signature"
    }
    return ed25519_verify(
        _bytes(public_key), jcs(unsigned), _bytes(signature.removeprefix("ed25519:"))
    )


# ---------------------------------------------------------------- DER


def _tlv(der: bytes, at: int) -> tuple[int, int, int]:
    """(tag, content start, end) of the DER element starting at `at`."""
    if at + 2 > len(der):
        raise FormError("truncated DER")
    tag, length, at = der[at], der[at + 1], at + 2
    if length & 0x80:
        size = length & 0x7F
        if not 1 <= size <= 4 or at + size > len(der):
            raise FormError("bad DER length")
        length, at = int.from_bytes(der[at : at + size], "big"), at + size
    if at + length > len(der):
        raise FormError("truncated DER")
    return tag, at, at + length


def certificate_spki(der: bytes) -> bytes:
    """The DER SubjectPublicKeyInfo (header included) of an X.509 certificate."""
    tag, start, end = _tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise FormError("not a certificate")
    tag, at, tbs_end = _tlv(der, start)
    if tag != 0x30:
        raise FormError("no TBSCertificate")
    fields = []
    while at < tbs_end:
        field_tag, _, field_end = _tlv(der, at)
        fields.append((field_tag, at, field_end))
        at = field_end
    first = 1 if fields and fields[0][0] == 0xA0 else 0  # optional [0] version
    if len(fields) < first + 6 or fields[first + 5][0] != 0x30:
        raise FormError("no SubjectPublicKeyInfo")
    _, spki_start, spki_end = fields[
        first + 5
    ]  # serial, signature, issuer, validity, subject, SPKI
    return der[spki_start:spki_end]


# ---------------------------------------------------------------- the checks


def _outcome(state: str, conformance: str, reason: str | None) -> dict[str, Any]:
    return {
        "evidence_state": state,
        "decision_conformance": conformance,
        "reason_code": reason,
    }


def _invalid(reason: str) -> dict[str, Any]:
    return _outcome("INVALID", "NOT_ASSESSABLE", reason)


def check_authorization(  # noqa: C901
    permit: Any, bundle: Any, context: dict[str, Any]
) -> dict[str, Any]:
    if bundle is None:
        return _outcome("UNVERIFIABLE", "NOT_ASSESSABLE", "TRUST_BUNDLE_UNAVAILABLE")
    try:
        check_permit_form(permit)
        keys = trust_keys(bundle)
        at = _time(context["at_time"])
        wire, peer = (
            _bytes(context["expected_wire_bytes_b64"]),
            _bytes(context["expected_peer_identity_b64"]),
        )
        jcs(context["expected_action"])
        jcs(context["expected_dispatch"])
    except FormError:
        return _invalid("SCHEMA_INVALID")
    if bundle["organisation_id"] != permit["organisation_id"]:
        return _invalid("ORGANISATION_MISMATCH")
    key = keys.get(permit["signer_key_id"])
    if key is None:
        return _invalid("TRUST_ROOT_UNKNOWN")
    if "execution_authorization_signer" not in key["usages"]:
        return _invalid("KEY_USAGE_INVALID")
    if not signature_holds(permit, key["public_key"]):
        return _invalid("EXECUTION_AUTHORIZATION_SIGNATURE_INVALID")
    if permit["trust_bundle_digest"] != digest_of(bundle):
        return _invalid("TRUST_BUNDLE_DIGEST_MISMATCH")
    wrong = [
        permit["request_id"] != context["expected_request_id"],
        permit["action_digest"] != digest_of(context["expected_action"]),
        jcs(permit["dispatch"]) != jcs(context["expected_dispatch"]),
        permit["expected_wire_bytes_digest"] != sha256_of_bytes(wire),
        permit["expected_wire_bytes_length"] != len(wire),
        permit["expected_peer_identity_digest"] != sha256_of_bytes(peer),
        any(permit[field] != context[f"expected_{field}"] for field in BINDINGS),
        not _time(permit["not_before"]) <= at < _time(permit["expires_at"]),
    ]
    if context["already_consumed"]:
        return _outcome(
            "VERIFIED", "NON_CONFORMANT", "EXECUTION_AUTHORIZATION_CONSUMED"
        )
    if any(wrong):
        return _outcome(
            "VERIFIED", "NON_CONFORMANT", "EXECUTION_AUTHORIZATION_NON_CONFORMANT"
        )
    if context["ledger_already_holds_id"]:
        return _outcome(
            "VERIFIED", "NON_CONFORMANT", "EXECUTION_AUTHORIZATION_CONSUMED"
        )
    return _outcome("VERIFIED", "CONFORMANT", None)


def check_presenter(
    permit: dict[str, Any], gate_requires_presenter: bool, certificate: bytes | None
) -> dict[str, Any]:
    bound = (
        permit["expected_presenter_identity_digest"]
        if permit["spec"] == PERMIT_V02
        else None
    )
    if bound is None:
        if gate_requires_presenter:
            return {"admitted": False, "reason_code": "RECEIVER_PRESENTER_REQUIRED"}
        return {"admitted": True, "reason_code": None}
    if not certificate:
        return {"admitted": False, "reason_code": "RECEIVER_PRESENTER_MISSING"}
    try:
        presented = sha256_of_bytes(certificate_spki(certificate))
    except FormError:
        return {"admitted": False, "reason_code": "RECEIVER_PRESENTER_MISMATCH"}
    if presented != bound:
        return {"admitted": False, "reason_code": "RECEIVER_PRESENTER_MISMATCH"}
    return {"admitted": True, "reason_code": None}


def check_witness(  # noqa: C901
    witness: Any, permit: Any, bundle: Any, observed: dict[str, Any]
) -> dict[str, Any]:
    if bundle is None:
        return _outcome("UNVERIFIABLE", "NOT_ASSESSABLE", "TRUST_BUNDLE_UNAVAILABLE")
    try:
        check_witness_form(witness)
        check_permit_form(permit)
        keys = trust_keys(bundle)
        jcs(_object(observed["action"]))
        check_dispatch_form(observed["dispatch"])
        wire, peer = (
            _bytes(observed["wire_bytes_b64"]),
            _bytes(observed["peer_identity_b64"]),
        )
    except FormError:
        return _invalid("SCHEMA_INVALID")
    organisation = permit["organisation_id"]
    if (
        bundle["organisation_id"] != organisation
        or witness["organisation_id"] != organisation
    ):
        return _invalid("ORGANISATION_MISMATCH")
    permit_key = keys.get(permit["signer_key_id"])
    if permit_key is None:
        return _invalid("AUTHORIZATION_TRUST_ROOT_UNKNOWN")
    if "execution_authorization_signer" not in permit_key["usages"]:
        return _invalid("AUTHORIZATION_KEY_USAGE_INVALID")
    witness_key = keys.get(witness["signer_key_id"])
    if witness_key is None:
        return _invalid("WITNESS_TRUST_ROOT_UNKNOWN")
    if "dispatch_witness_signer" not in witness_key["usages"]:
        return _invalid("WITNESS_KEY_USAGE_INVALID")
    if any(
        permit_key[field] == witness_key[field]
        for field in ("key_id", "public_key", "principal")
    ):
        return _invalid("WITNESS_NOT_INDEPENDENT")
    if not signature_holds(permit, permit_key["public_key"]):
        return _invalid("EXECUTION_AUTHORIZATION_SIGNATURE_INVALID")
    if not signature_holds(witness, witness_key["public_key"]):
        return _invalid("DISPATCH_WITNESS_SIGNATURE_INVALID")
    bundle_digest = digest_of(bundle)
    if (
        permit["trust_bundle_digest"] != bundle_digest
        or witness["trust_bundle_digest"] != bundle_digest
    ):
        return _invalid("TRUST_BUNDLE_DIGEST_MISMATCH")
    observed_action_digest = digest_of(observed["action"])
    wrong = [
        any(
            witness[field] != permit[field]
            for field in ("organisation_id", "request_id", "execution_authorization_id")
        ),
        witness["execution_authorization_digest"] != digest_of(permit),
        witness["observed_action_digest"] != observed_action_digest,
        permit["action_digest"] != observed_action_digest,
        jcs(witness["observed_dispatch"]) != jcs(observed["dispatch"]),
        jcs(permit["dispatch"]) != jcs(observed["dispatch"]),
        witness["wire_bytes_digest"] != sha256_of_bytes(wire),
        permit["expected_wire_bytes_digest"] != sha256_of_bytes(wire),
        witness["wire_bytes_length"] != len(wire),
        permit["expected_wire_bytes_length"] != len(wire),
        witness["peer_identity_digest"] != sha256_of_bytes(peer),
        permit["expected_peer_identity_digest"] != sha256_of_bytes(peer),
        not _time(permit["not_before"])
        <= _time(witness["observed_at"])
        < _time(permit["expires_at"]),
        witness["attempt"] != 1,
    ]
    if any(wrong):
        return _outcome("VERIFIED", "NON_CONFORMANT", "DISPATCH_NON_CONFORMANT")
    return _outcome("VERIFIED", "CONFORMANT", None)


def check_wire_binding(
    action: dict[str, Any], serialization: Any, digest: Any, length: Any
) -> dict[str, Any]:
    if not isinstance(serialization, str) or not serialization:
        return {"reason_code": "AUTHORIZE_WIRE_SERIALIZATION_REQUIRED"}
    if serialization != SERIALIZATION:
        return {"reason_code": "AUTHORIZE_WIRE_SERIALIZATION_UNKNOWN"}
    # pv-json-parameters/0.1: UTF-8 JSON of action.parameters, keys sorted by
    # code point, no whitespace, non-ASCII unescaped, NaN and Infinity refused.
    wire = json.dumps(
        action["parameters"],
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    if digest != sha256_of_bytes(wire) or length != len(wire):
        return {"reason_code": "AUTHORIZE_WIRE_ACTION_MISMATCH"}
    return {"reason_code": None}


# ---------------------------------------------------------------- driver


def run(vectors: dict[str, Any]) -> list[str]:
    """Return one line per disagreement; an empty list means full agreement."""
    disagreements: list[str] = []
    bundles = vectors["trust_bundles"]
    permits = {
        case["id"]: case["authorization"] for case in vectors["authorization_cases"]
    }

    def compare(case: dict[str, Any], computed: dict[str, Any]) -> None:
        recorded = {field: case["expect"].get(field) for field in computed}
        if computed != recorded:
            disagreements.append(
                f"{case['id']}: computed {computed}, file records {recorded}"
            )

    fixtures = vectors["fixtures"]
    ea01 = permits["EA-01"]
    if jcs({k: v for k, v in ea01.items() if k != "signature"}) != _bytes(
        fixtures["ea01_signing_input_b64"]
    ):
        disagreements.append(
            "fixtures: RFC 8785 bytes of EA-01 differ from ea01_signing_input_b64"
        )
    if digest_of(ea01) != fixtures["ea01_authorization_digest"]:
        disagreements.append(
            "fixtures: digest of EA-01 differs from ea01_authorization_digest"
        )

    for case in vectors["authorization_cases"]:
        bundle = bundles[case["trust_bundle"]] if case["trust_bundle"] else None
        compare(
            case, check_authorization(case["authorization"], bundle, case["context"])
        )
    for case in vectors["presenter_cases"]:
        certificate = (
            _bytes(case["client_certificate_der_b64"])
            if case["client_certificate_der_b64"] is not None
            else None
        )
        compare(
            case,
            check_presenter(
                permits[case["authorization_case"]],
                case["gate_requires_presenter"],
                certificate,
            ),
        )
    for case in vectors["witness_cases"]:
        compare(
            case,
            check_witness(
                case["witness"],
                permits[case["authorization_case"]],
                bundles[case["trust_bundle"]],
                case["observed"],
            ),
        )
    for case in vectors["wire_binding_cases"]:
        compare(
            case,
            check_wire_binding(
                case["action"],
                case["serialization"],
                case["expected_wire_bytes_digest"],
                case["expected_wire_bytes_length"],
            ),
        )
    return disagreements


def main(argv: list[str]) -> int:
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT_VECTORS
    vectors = json.loads(path.read_text(encoding="utf-8"))
    sections = (
        "authorization_cases",
        "presenter_cases",
        "witness_cases",
        "wire_binding_cases",
    )
    total = sum(len(vectors[section]) for section in sections)
    disagreements = run(vectors)
    for line in disagreements:
        print(f"DISAGREE {line}")
    failed_cases = {line.split(":", 1)[0] for line in disagreements} - {"fixtures"}
    print(
        f"{total - len(failed_cases)} of {total} cases agree; fixtures {'differ' if any(line.startswith('fixtures') for line in disagreements) else 'agree'}"
    )
    return 1 if disagreements else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
