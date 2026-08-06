"""Authority Provenance v0.1-experimental.

This module is intentionally separate from agent_dna.grants. The existing
GrantRegistry is an online lifecycle and budget authorizer. This protocol is
an offline-verifiable authority-evidence format.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, NoReturn, cast

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

TRUST_SPEC = "pv-trust-bundle/0.1-experimental"
GRANT_SPEC = "pv-grant/0.1-experimental"
RECEIPT_SPEC = "pv-authority-receipt/0.1-experimental"
CANONICALIZATION = "RFC8785"
COMPOSITION_PROFILE = "pv-fail-closed/0.1"

SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
SIGNATURE_RE = re.compile(r"ed25519:[A-Za-z0-9+/]+={0,2}\Z")
RESOURCE_RE = re.compile(r"[^*]+(?::\*)?\Z")
ISO_CURRENCY_RE = re.compile(r"[A-Z]{3}\Z")
RFC3339_UTC_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z\Z")
SUPPORTED_OPERATORS = frozenset({"lte", "gte", "in", "not_in", "eq"})
SUPPORTED_USAGES = frozenset(
    {
        "root_authority",
        "grant_issuer",
        "subject",
        "receipt_signer",
        "approval_signer",
        "execution_authorization_signer",
        "dispatch_witness_signer",
        "closure_signer",
    }
)
VERDICTS = frozenset({"ALLOW", "DENY", "REQUIRE_APPROVAL"})
MAX_SAFE_INTEGER = (1 << 53) - 1


class AuthorityFormatError(ValueError):
    """Strict parsing or schema failure."""


class EvidenceState(StrEnum):
    VERIFIED = "VERIFIED"
    INVALID = "INVALID"
    UNVERIFIABLE = "UNVERIFIABLE"
    ABSENT = "ABSENT"


class DecisionConformance(StrEnum):
    CONFORMANT = "CONFORMANT"
    NON_CONFORMANT = "NON_CONFORMANT"
    NOT_ASSESSABLE = "NOT_ASSESSABLE"


@dataclass(frozen=True)
class VerificationReport:
    evidence_state: EvidenceState
    decision_conformance: DecisionConformance
    reason_code: str | None = None
    failures: tuple[str, ...] = ()
    accountable_principal: str | None = None

    @property
    def ok(self) -> bool:
        return (
            self.evidence_state is EvidenceState.VERIFIED
            and self.decision_conformance is DecisionConformance.CONFORMANT
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_state": self.evidence_state.value,
            "decision_conformance": self.decision_conformance.value,
            "reason_code": self.reason_code,
            "failures": list(self.failures),
            "accountable_principal": self.accountable_principal,
        }


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AuthorityFormatError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_constant(token: str) -> None:
    raise AuthorityFormatError(f"non-finite JSON number: {token}")


def strict_json_loads(data: str | bytes) -> Any:
    """Parse strict JSON and reject duplicate keys and non-finite numbers."""

    try:
        value = json.loads(
            data,
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise AuthorityFormatError(f"invalid JSON: {exc}") from exc
    _validate_json_value(value)
    return value


def _validate_json_value(value: Any, path: str = "$") -> None:  # noqa: C901
    if value is None or isinstance(value, (str, bool)):
        if isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise AuthorityFormatError(
                    f"{path}: invalid Unicode scalar value"
                ) from exc
        return

    if isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise AuthorityFormatError(f"{path}: integer outside I-JSON range")
        return

    if isinstance(value, float):
        raise AuthorityFormatError(
            f"{path}: floating point is forbidden in authority artifacts"
        )

    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]")
        return

    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise AuthorityFormatError(f"{path}: object key is not a string")
            _validate_json_value(key, f"{path}.<key>")
            _validate_json_value(item, f"{path}.{key}")
        return

    raise AuthorityFormatError(f"{path}: unsupported JSON value {type(value).__name__}")


def _utf16_sort_key(value: str) -> bytes:
    try:
        return value.encode("utf-16-be")
    except UnicodeEncodeError as exc:
        raise AuthorityFormatError("invalid Unicode scalar value") from exc


def canonicalize(value: Any) -> bytes:
    """Canonicalize the protocol's float-free I-JSON subset using RFC 8785."""

    _validate_json_value(value)

    def encode(item: Any) -> str:
        if item is None:
            return "null"
        if item is True:
            return "true"
        if item is False:
            return "false"
        if isinstance(item, int):
            return str(item)
        if isinstance(item, str):
            return json.dumps(
                item,
                ensure_ascii=False,
                separators=(",", ":"),
            )
        if isinstance(item, list):
            return "[" + ",".join(encode(child) for child in item) + "]"
        if isinstance(item, dict):
            ordered = sorted(item, key=_utf16_sort_key)
            return (
                "{"
                + ",".join(f"{encode(key)}:{encode(item[key])}" for key in ordered)
                + "}"
            )
        raise AuthorityFormatError(f"unsupported value {type(item).__name__}")

    return encode(value).encode("utf-8")


def _unsigned(
    document: Mapping[str, Any],
    signature_field: str,
) -> dict[str, Any]:
    return {key: value for key, value in document.items() if key != signature_field}


def sha256_digest(value: Any) -> str:
    return f"sha256:{hashlib.sha256(canonicalize(value)).hexdigest()}"


def grant_digest(grant: Mapping[str, Any]) -> str:
    """Digest the complete signed grant for parent linkage."""

    return sha256_digest(grant)


def receipt_digest(receipt: Mapping[str, Any]) -> str:
    """Digest the complete signed receipt for sequence linkage."""

    return sha256_digest(receipt)


def _signature_bytes(value: Any) -> bytes:
    if not isinstance(value, str) or not SIGNATURE_RE.fullmatch(value):
        raise AuthorityFormatError("malformed Ed25519 signature")

    try:
        decoded = base64.b64decode(
            value.removeprefix("ed25519:"),
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise AuthorityFormatError("malformed Ed25519 signature") from exc

    if len(decoded) != 64:
        raise AuthorityFormatError("Ed25519 signature must be 64 bytes")

    return decoded


def _public_key_bytes(value: Any) -> bytes:
    if not isinstance(value, str):
        raise AuthorityFormatError("public_key must be base64")

    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise AuthorityFormatError("public_key must be valid base64") from exc

    if len(decoded) != 32:
        raise AuthorityFormatError("Ed25519 public key must be 32 bytes")

    return decoded


def sign_document(
    document: Mapping[str, Any],
    signing_key: SigningKey,
    *,
    signature_field: str,
) -> dict[str, Any]:
    """Sign every document field except the detached signature field."""

    result = dict(document)
    result.pop(signature_field, None)

    signature = signing_key.sign(canonicalize(result)).signature
    result[signature_field] = "ed25519:" + base64.b64encode(signature).decode("ascii")
    return result


def sign_grant(
    grant: Mapping[str, Any],
    signing_key: SigningKey,
) -> dict[str, Any]:
    return sign_document(
        grant,
        signing_key,
        signature_field="issuer_signature",
    )


def sign_receipt(
    receipt: Mapping[str, Any],
    signing_key: SigningKey,
) -> dict[str, Any]:
    return sign_document(
        receipt,
        signing_key,
        signature_field="signature",
    )


def encode_public_key(signing_key: SigningKey) -> str:
    return base64.b64encode(bytes(signing_key.verify_key)).decode("ascii")


def _verify_signature(
    document: Mapping[str, Any],
    *,
    signature_field: str,
    public_key: Any,
) -> bool:
    signature = _signature_bytes(document.get(signature_field))

    VerifyKey(_public_key_bytes(public_key)).verify(
        canonicalize(_unsigned(document, signature_field)),
        signature,
    )
    return True


def verify_document_signature(
    document: Mapping[str, Any],
    *,
    signature_field: str,
    public_key: Any,
) -> bool:
    """Verify a canonical Ed25519-signed document."""
    return _verify_signature(
        document,
        signature_field=signature_field,
        public_key=public_key,
    )


def _require_object(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise AuthorityFormatError(f"{path}: expected object")
    return value


def _require_fields(
    value: Mapping[str, Any],
    *,
    required: Iterable[str],
    optional: Iterable[str] = (),
    path: str,
) -> None:
    required_set = frozenset(required)
    allowed = required_set | frozenset(optional)
    actual = frozenset(value)

    missing = required_set - actual
    unknown = actual - allowed

    if missing:
        raise AuthorityFormatError(f"{path}: missing fields {sorted(missing)}")

    if unknown:
        raise AuthorityFormatError(f"{path}: unknown fields {sorted(unknown)}")


def _require_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise AuthorityFormatError(f"{path}: expected non-empty string")
    return value


def _parse_timestamp(value: Any, path: str) -> datetime:
    text = _require_string(value, path)

    if not RFC3339_UTC_RE.fullmatch(text):
        raise AuthorityFormatError(
            f"{path}: timestamp must be RFC 3339 UTC with second precision"
        )

    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise AuthorityFormatError(f"{path}: malformed timestamp") from exc

    return parsed


def _validate_money(value: Any, path: str) -> tuple[int, str]:
    money = _require_object(value, path)

    _require_fields(
        money,
        required={"minor_units", "currency"},
        path=path,
    )

    amount = money["minor_units"]
    currency = money["currency"]

    if isinstance(amount, bool) or not isinstance(amount, int):
        raise AuthorityFormatError(f"{path}.minor_units: expected integer")

    if not -MAX_SAFE_INTEGER <= amount <= MAX_SAFE_INTEGER:
        raise AuthorityFormatError(f"{path}.minor_units: outside I-JSON range")

    if not isinstance(currency, str) or not ISO_CURRENCY_RE.fullmatch(currency):
        raise AuthorityFormatError(f"{path}.currency: expected ISO 4217 code")

    return amount, currency


def _validate_comparable(value: Any, path: str) -> None:
    if isinstance(value, bool):
        raise AuthorityFormatError(f"{path}: boolean is not an ordered value")

    if isinstance(value, int):
        return

    if isinstance(value, Mapping):
        _validate_money(value, path)
        return

    raise AuthorityFormatError(f"{path}: expected integer or money object")


def _validate_constraint(value: Any, path: str) -> None:
    constraint = _require_object(value, path)

    _require_fields(
        constraint,
        required={"field", "operator", "value"},
        path=path,
    )

    _require_string(constraint["field"], f"{path}.field")

    operator = constraint["operator"]
    if operator not in SUPPORTED_OPERATORS:
        raise AuthorityFormatError(f"{path}.operator: unsupported operator")

    declared = constraint["value"]

    if operator in {"lte", "gte"}:
        _validate_comparable(declared, f"{path}.value")

    elif operator in {"in", "not_in"}:
        if not isinstance(declared, list) or not declared:
            raise AuthorityFormatError(f"{path}.value: expected non-empty list")

        fingerprints = [canonicalize(item) for item in declared]

        if len(fingerprints) != len(set(fingerprints)):
            raise AuthorityFormatError(f"{path}.value: duplicate set member")

    else:
        _validate_json_value(declared, f"{path}.value")


def _validate_capability(value: Any, path: str) -> None:
    capability = _require_object(value, path)

    _require_fields(
        capability,
        required={
            "action",
            "resource",
            "constraints",
            "obligations",
        },
        path=path,
    )

    action = _require_string(
        capability["action"],
        f"{path}.action",
    )

    if "*" in action:
        raise AuthorityFormatError(f"{path}.action: wildcards are not supported")

    resource = _require_string(
        capability["resource"],
        f"{path}.resource",
    )

    if not RESOURCE_RE.fullmatch(resource):
        raise AuthorityFormatError(
            f"{path}.resource: only a single trailing ':*' wildcard is permitted"
        )

    constraints = capability["constraints"]
    obligations = capability["obligations"]

    if not isinstance(constraints, list):
        raise AuthorityFormatError(f"{path}.constraints: expected list")

    if not isinstance(obligations, list):
        raise AuthorityFormatError(f"{path}.obligations: expected list")

    fields: set[str] = set()

    for index, constraint in enumerate(constraints):
        _validate_constraint(
            constraint,
            f"{path}.constraints[{index}]",
        )

        field = constraint["field"]

        if field in fields:
            raise AuthorityFormatError(f"{path}.constraints: duplicate field {field!r}")

        fields.add(field)

    fingerprints = [canonicalize(item) for item in obligations]

    if len(fingerprints) != len(set(fingerprints)):
        raise AuthorityFormatError(f"{path}.obligations: duplicate obligation")


def validate_trust_bundle(
    bundle: Any,
) -> dict[str, Mapping[str, Any]]:
    trust = _require_object(bundle, "trust_bundle")

    _require_fields(
        trust,
        required={
            "spec",
            "canonicalization",
            "organisation_id",
            "bundle_version",
            "pinned_at",
            "keys",
        },
        path="trust_bundle",
    )

    if trust["spec"] != TRUST_SPEC:
        raise AuthorityFormatError("trust_bundle.spec: unsupported spec")

    if trust["canonicalization"] != CANONICALIZATION:
        raise AuthorityFormatError(
            "trust_bundle.canonicalization: unsupported canonicalization"
        )

    _require_string(
        trust["organisation_id"],
        "trust_bundle.organisation_id",
    )

    version = trust["bundle_version"]

    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise AuthorityFormatError("trust_bundle.bundle_version: expected integer >= 1")

    _parse_timestamp(
        trust["pinned_at"],
        "trust_bundle.pinned_at",
    )

    if not isinstance(trust["keys"], list) or not trust["keys"]:
        raise AuthorityFormatError("trust_bundle.keys: expected non-empty list")

    keys: dict[str, Mapping[str, Any]] = {}

    for index, item in enumerate(trust["keys"]):
        path = f"trust_bundle.keys[{index}]"
        key = _require_object(item, path)

        _require_fields(
            key,
            required={
                "key_id",
                "principal",
                "algorithm",
                "public_key",
                "usages",
            },
            path=path,
        )

        key_id = _require_string(
            key["key_id"],
            f"{path}.key_id",
        )

        _require_string(
            key["principal"],
            f"{path}.principal",
        )

        if key["algorithm"] != "ed25519":
            raise AuthorityFormatError(f"{path}.algorithm: unsupported algorithm")

        _public_key_bytes(key["public_key"])

        usages = key["usages"]

        if not isinstance(usages, list) or not usages:
            raise AuthorityFormatError(f"{path}.usages: expected non-empty list")

        if (
            any(not isinstance(usage, str) for usage in usages)
            or not set(usages) <= SUPPORTED_USAGES
            or len(usages) != len(set(usages))
        ):
            raise AuthorityFormatError(f"{path}.usages: invalid or duplicate usage")

        if key_id in keys:
            raise AuthorityFormatError(f"trust_bundle.keys: duplicate key_id {key_id}")

        keys[key_id] = key

    return keys


def validate_grant(
    grant: Any,
    path: str = "grant",
) -> Mapping[str, Any]:
    value = _require_object(grant, path)

    _require_fields(
        value,
        required={
            "spec",
            "canonicalization",
            "grant_id",
            "organisation_id",
            "issuer_principal",
            "issuer_key_id",
            "subject_principal",
            "subject_key_id",
            "parent_grant_digest",
            "capabilities",
            "can_delegate",
            "remaining_depth",
            "valid_from",
            "expires_at",
            "issuer_signature",
        },
        path=path,
    )

    if value["spec"] != GRANT_SPEC:
        raise AuthorityFormatError(f"{path}.spec: unsupported spec")

    if value["canonicalization"] != CANONICALIZATION:
        raise AuthorityFormatError(f"{path}.canonicalization: unsupported")

    for field in (
        "grant_id",
        "organisation_id",
        "issuer_principal",
        "issuer_key_id",
        "subject_principal",
        "subject_key_id",
    ):
        _require_string(
            value[field],
            f"{path}.{field}",
        )

    parent = value["parent_grant_digest"]

    if parent is not None and (
        not isinstance(parent, str) or not SHA256_RE.fullmatch(parent)
    ):
        raise AuthorityFormatError(f"{path}.parent_grant_digest: malformed digest")

    capabilities = value["capabilities"]

    if not isinstance(capabilities, list) or not capabilities:
        raise AuthorityFormatError(f"{path}.capabilities: expected non-empty list")

    for index, capability in enumerate(capabilities):
        _validate_capability(
            capability,
            f"{path}.capabilities[{index}]",
        )

    if not isinstance(value["can_delegate"], bool):
        raise AuthorityFormatError(f"{path}.can_delegate: expected boolean")

    depth = value["remaining_depth"]

    if isinstance(depth, bool) or not isinstance(depth, int) or depth < 0:
        raise AuthorityFormatError(f"{path}.remaining_depth: expected integer >= 0")

    valid_from = _parse_timestamp(
        value["valid_from"],
        f"{path}.valid_from",
    )

    expires_at = _parse_timestamp(
        value["expires_at"],
        f"{path}.expires_at",
    )

    if valid_from >= expires_at:
        raise AuthorityFormatError(f"{path}: validity interval is empty or inverted")

    _signature_bytes(value["issuer_signature"])

    return value


def validate_receipt(  # noqa: C901
    receipt: Any,
    path: str = "receipt",
) -> Mapping[str, Any]:
    value = _require_object(receipt, path)

    _require_fields(
        value,
        required={
            "spec",
            "canonicalization",
            "receipt_id",
            "organisation_id",
            "previous_receipt_hash",
            "request_id",
            "decision_timestamp",
            "decision_input_digest",
            "grant_chain",
            "requested",
            "authority_result",
            "policy_result",
            "composition_profile",
            "final_verdict",
            "signer_key_id",
            "signature",
        },
        path=path,
    )

    if value["spec"] != RECEIPT_SPEC:
        raise AuthorityFormatError(f"{path}.spec: unsupported spec")

    if value["canonicalization"] != CANONICALIZATION:
        raise AuthorityFormatError(f"{path}.canonicalization: unsupported")

    for field in (
        "receipt_id",
        "organisation_id",
        "request_id",
        "signer_key_id",
    ):
        _require_string(value[field], f"{path}.{field}")

    previous = value["previous_receipt_hash"]

    if previous is not None and (
        not isinstance(previous, str) or not SHA256_RE.fullmatch(previous)
    ):
        raise AuthorityFormatError(f"{path}.previous_receipt_hash: malformed digest")

    _parse_timestamp(
        value["decision_timestamp"],
        f"{path}.decision_timestamp",
    )

    digest = value["decision_input_digest"]

    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise AuthorityFormatError(f"{path}.decision_input_digest: malformed digest")

    grant_chain = value["grant_chain"]

    if not isinstance(grant_chain, list) or not grant_chain:
        raise AuthorityFormatError(f"{path}.grant_chain: expected non-empty list")

    for index, grant in enumerate(grant_chain):
        validate_grant(
            grant,
            f"{path}.grant_chain[{index}]",
        )

    requested = _require_object(
        value["requested"],
        f"{path}.requested",
    )

    _require_fields(
        requested,
        required={
            "subject_principal",
            "subject_key_id",
            "action",
            "resource",
            "facts",
        },
        path=f"{path}.requested",
    )

    for field in (
        "subject_principal",
        "subject_key_id",
        "action",
        "resource",
    ):
        _require_string(
            requested[field],
            f"{path}.requested.{field}",
        )

    if not isinstance(requested["facts"], Mapping):
        raise AuthorityFormatError(f"{path}.requested.facts: expected object")

    _validate_json_value(
        requested["facts"],
        f"{path}.requested.facts",
    )

    authority = _require_object(
        value["authority_result"],
        f"{path}.authority_result",
    )

    _require_fields(
        authority,
        required={"verdict", "reason_code"},
        path=f"{path}.authority_result",
    )

    if authority["verdict"] not in VERDICTS:
        raise AuthorityFormatError(f"{path}.authority_result.verdict: invalid")

    _require_string(
        authority["reason_code"],
        f"{path}.authority_result.reason_code",
    )

    policy = value["policy_result"]

    # A missing evaluator result is explicitly encoded as JSON null.
    # The field remains required so stripping it is detectable.
    if policy is not None:
        policy = _require_object(
            policy,
            f"{path}.policy_result",
        )

        _require_fields(
            policy,
            required={
                "verdict",
                "policy_id",
                "policy_version",
                "policy_digest",
            },
            path=f"{path}.policy_result",
        )

        if policy["verdict"] not in VERDICTS:
            raise AuthorityFormatError(f"{path}.policy_result.verdict: invalid")

        for field in ("policy_id", "policy_version"):
            _require_string(
                policy[field],
                f"{path}.policy_result.{field}",
            )

        policy_digest = policy["policy_digest"]

        if not isinstance(policy_digest, str) or not SHA256_RE.fullmatch(policy_digest):
            raise AuthorityFormatError(f"{path}.policy_result.policy_digest: malformed")

    if value["composition_profile"] != COMPOSITION_PROFILE:
        raise AuthorityFormatError(f"{path}.composition_profile: unsupported")

    if value["final_verdict"] not in VERDICTS:
        raise AuthorityFormatError(f"{path}.final_verdict: invalid")

    _signature_bytes(value["signature"])

    return value


def _compare_ordered(
    left: Any,
    right: Any,
    *,
    operator: str,
) -> bool:
    if isinstance(left, int) and not isinstance(left, bool):
        if not isinstance(right, int) or isinstance(right, bool):
            return False

        return left <= right if operator == "lte" else left >= right

    if isinstance(left, Mapping) and isinstance(right, Mapping):
        left_amount, left_currency = _validate_money(left, "left")
        right_amount, right_currency = _validate_money(right, "right")

        if left_currency != right_currency:
            return False

        return (
            left_amount <= right_amount
            if operator == "lte"
            else left_amount >= right_amount
        )

    return False


def _set_fingerprints(values: Sequence[Any]) -> set[bytes]:
    return {canonicalize(item) for item in values}


def constraint_contains(
    parent: Mapping[str, Any],
    child: Mapping[str, Any],
) -> bool:
    if parent.get("field") != child.get("field"):
        return False

    operator = parent.get("operator")

    if operator != child.get("operator"):
        return False

    parent_value = parent.get("value")
    child_value = child.get("value")

    if operator == "lte":
        return _compare_ordered(
            child_value,
            parent_value,
            operator="lte",
        )

    if operator == "gte":
        return _compare_ordered(
            child_value,
            parent_value,
            operator="gte",
        )

    if operator == "in":
        return _set_fingerprints(cast(list[Any], child_value)) <= _set_fingerprints(
            cast(list[Any], parent_value)
        )

    if operator == "not_in":
        return _set_fingerprints(cast(list[Any], child_value)) >= _set_fingerprints(
            cast(list[Any], parent_value)
        )

    if operator == "eq":
        return canonicalize(child_value) == canonicalize(parent_value)

    return False


def _resource_contains(parent: str, child: str) -> bool:
    if parent == child:
        return True

    if not parent.endswith(":*"):
        return False

    return child.startswith(parent[:-1])


def resource_matches(pattern: str, resource: str) -> bool:
    return pattern == resource or (
        pattern.endswith(":*") and resource.startswith(pattern[:-1])
    )


def contains(
    parent_capability: Mapping[str, Any],
    child_capability: Mapping[str, Any],
) -> bool:
    """Return whether a child capability is no broader than its parent."""

    _validate_capability(
        parent_capability,
        "parent_capability",
    )

    _validate_capability(
        child_capability,
        "child_capability",
    )

    if parent_capability["action"] != child_capability["action"]:
        return False

    if not _resource_contains(
        parent_capability["resource"],
        child_capability["resource"],
    ):
        return False

    child_constraints = {
        item["field"]: item for item in child_capability["constraints"]
    }

    # Every parent constraint must remain present in the child.
    # Absence never means implicit inheritance.
    for parent_constraint in parent_capability["constraints"]:
        child_constraint = child_constraints.get(parent_constraint["field"])

        if child_constraint is None:
            return False

        if not constraint_contains(
            parent_constraint,
            child_constraint,
        ):
            return False

    parent_obligations = _set_fingerprints(parent_capability["obligations"])

    child_obligations = _set_fingerprints(child_capability["obligations"])

    # A child may add obligations but may never shed a parent obligation.
    return parent_obligations <= child_obligations


def _constraint_satisfied(
    constraint: Mapping[str, Any],
    fact: Any,
) -> bool:
    operator = constraint["operator"]
    expected = constraint["value"]

    if operator == "lte":
        return _compare_ordered(
            fact,
            expected,
            operator="lte",
        )

    if operator == "gte":
        return _compare_ordered(
            fact,
            expected,
            operator="gte",
        )

    if operator == "in":
        return canonicalize(fact) in _set_fingerprints(expected)

    if operator == "not_in":
        return canonicalize(fact) not in _set_fingerprints(expected)

    if operator == "eq":
        return canonicalize(fact) == canonicalize(expected)

    return False


def satisfies(
    request_facts: Mapping[str, Any],
    leaf_capability: Mapping[str, Any],
) -> tuple[bool, str | None]:
    """Evaluate concrete facts against one leaf capability."""

    _validate_capability(
        leaf_capability,
        "leaf_capability",
    )

    _validate_json_value(
        request_facts,
        "request_facts",
    )

    for constraint in leaf_capability["constraints"]:
        field = constraint["field"]

        if field not in request_facts:
            return False, "CONSTRAINT_FACT_MISSING"

        try:
            satisfied = _constraint_satisfied(
                constraint,
                request_facts[field],
            )
        except AuthorityFormatError:
            satisfied = False

        if not satisfied:
            return False, "CONSTRAINT_NOT_SATISFIED"

    return True, None


def evaluate_authority(
    requested: Mapping[str, Any],
    leaf_grant: Mapping[str, Any],
) -> dict[str, str]:
    matching: list[Mapping[str, Any]] = []

    for capability in leaf_grant["capabilities"]:
        if capability["action"] == requested["action"] and resource_matches(
            capability["resource"],
            requested["resource"],
        ):
            matching.append(capability)

    if not matching:
        return {
            "verdict": "DENY",
            "reason_code": "ACTION_OUTSIDE_DELEGATED_AUTHORITY",
        }

    failures: list[str] = []

    for capability in matching:
        ok, reason = satisfies(
            requested["facts"],
            capability,
        )

        if ok:
            return {
                "verdict": "ALLOW",
                "reason_code": "AUTHORITY_GRANTED",
            }

        if reason is not None:
            failures.append(reason)

    reason = (
        "CONSTRAINT_FACT_MISSING"
        if "CONSTRAINT_FACT_MISSING" in failures
        else "CONSTRAINT_NOT_SATISFIED"
    )

    return {
        "verdict": "DENY",
        "reason_code": reason,
    }


def compose_final(
    authority_result: Mapping[str, Any] | None,
    policy_result: Mapping[str, Any] | None,
    profile: str,
) -> str:
    if profile != COMPOSITION_PROFILE:
        return "DENY"

    if not authority_result or authority_result.get("verdict") != "ALLOW":
        verdict = authority_result.get("verdict") if authority_result else None

        return verdict if verdict in VERDICTS else "DENY"

    policy_verdict = policy_result.get("verdict") if policy_result else None

    if policy_verdict in VERDICTS:
        return cast(str, policy_verdict)

    return "DENY"


class _InvalidEvidenceError(Exception):
    def __init__(self, reason_code: str, detail: str):
        super().__init__(detail)
        self.reason_code = reason_code
        self.detail = detail


def _invalid(reason_code: str, detail: str) -> NoReturn:
    raise _InvalidEvidenceError(reason_code, detail)


def _resolve_key(
    keys: Mapping[str, Mapping[str, Any]],
    key_id: str,
    *,
    principal: str | None = None,
    usage: str | None = None,
) -> Mapping[str, Any]:
    key = keys.get(key_id)

    if key is None:
        _invalid(
            "TRUST_ROOT_UNKNOWN",
            f"key {key_id!r} is absent from trust bundle",
        )

    if principal is not None and key["principal"] != principal:
        _invalid(
            "KEY_CONTINUITY_BROKEN",
            f"key {key_id!r} belongs to {key['principal']!r}, not {principal!r}",
        )

    if usage is not None and usage not in key["usages"]:
        _invalid(
            "KEY_USAGE_INVALID",
            f"key {key_id!r} lacks required usage {usage!r}",
        )

    return key


def _verify_evidence(  # noqa: C901
    receipt: Mapping[str, Any],
    bundle: Mapping[str, Any],
    *,
    expected_previous_hash: str | None,
    check_previous: bool,
) -> str:
    try:
        keys = validate_trust_bundle(bundle)
        validate_receipt(receipt)
    except AuthorityFormatError as exc:
        _invalid("SCHEMA_INVALID", str(exc))

    if receipt["organisation_id"] != bundle["organisation_id"]:
        _invalid(
            "CHAIN_DISCONTINUOUS",
            "receipt and trust bundle organisation differ",
        )

    signer = _resolve_key(
        keys,
        receipt["signer_key_id"],
        usage="receipt_signer",
    )

    try:
        _verify_signature(
            receipt,
            signature_field="signature",
            public_key=signer["public_key"],
        )
    except (AuthorityFormatError, BadSignatureError):
        _invalid(
            "RECEIPT_SIGNATURE_INVALID",
            "receipt signature is invalid",
        )

    if check_previous and receipt["previous_receipt_hash"] != expected_previous_hash:
        _invalid(
            "CHAIN_DISCONTINUOUS",
            "previous_receipt_hash does not match supplied predecessor",
        )

    chain = receipt["grant_chain"]

    decision_time = _parse_timestamp(
        receipt["decision_timestamp"],
        "receipt.decision_timestamp",
    )

    # This represents the authority path:
    # root issuer -> root subject -> child subject -> ...
    authority_nodes: list[tuple[str, str]] = []

    for index, grant in enumerate(chain):
        if grant["organisation_id"] != bundle["organisation_id"]:
            _invalid(
                "CHAIN_DISCONTINUOUS",
                f"grant {grant['grant_id']!r} belongs to another organisation",
            )

        issuer_key = _resolve_key(
            keys,
            grant["issuer_key_id"],
            principal=grant["issuer_principal"],
            usage="grant_issuer",
        )

        try:
            _verify_signature(
                grant,
                signature_field="issuer_signature",
                public_key=issuer_key["public_key"],
            )
        except (AuthorityFormatError, BadSignatureError):
            _invalid(
                "GRANT_SIGNATURE_INVALID",
                f"grant {grant['grant_id']!r} signature is invalid",
            )

        valid_from = _parse_timestamp(
            grant["valid_from"],
            "grant.valid_from",
        )

        expires_at = _parse_timestamp(
            grant["expires_at"],
            "grant.expires_at",
        )

        # Half-open interval. Verification wall-clock time is irrelevant.
        if not valid_from <= decision_time < expires_at:
            _invalid(
                "GRANT_NOT_VALID_AT_DECISION_TIME",
                f"grant {grant['grant_id']!r} is not valid at decision time",
            )

        if index == 0:
            if grant["parent_grant_digest"] is not None:
                _invalid(
                    "CHAIN_DISCONTINUOUS",
                    "root grant has a parent digest",
                )

            if "root_authority" not in issuer_key["usages"]:
                _invalid(
                    "KEY_USAGE_INVALID",
                    "root grant issuer key lacks root_authority usage",
                )

            # Derived only from the pinned bundle, never the receipt.
            accountable_principal = issuer_key["principal"]

            authority_nodes.append(
                (
                    grant["issuer_principal"],
                    grant["issuer_key_id"],
                )
            )

        else:
            parent = chain[index - 1]

            if grant["parent_grant_digest"] != grant_digest(parent):
                _invalid(
                    "CHAIN_DISCONTINUOUS",
                    f"grant {grant['grant_id']!r} does not link to its parent",
                )

            if (
                parent["subject_principal"] != grant["issuer_principal"]
                or parent["subject_key_id"] != grant["issuer_key_id"]
            ):
                _invalid(
                    "KEY_CONTINUITY_BROKEN",
                    f"grant {grant['grant_id']!r} issuer is not its parent subject",
                )

            # Parent authority controls whether delegation may occur.
            # The child's can_delegate flag controls only a future hop.
            if not parent["can_delegate"]:
                _invalid(
                    "DELEGATION_NOT_PERMITTED",
                    f"grant {parent['grant_id']!r} cannot delegate",
                )

            if parent["remaining_depth"] <= 0 or not (
                grant["remaining_depth"] < parent["remaining_depth"]
            ):
                _invalid(
                    "DELEGATION_DEPTH_EXCEEDED",
                    "remaining_depth did not strictly decrease",
                )

            parent_from = _parse_timestamp(
                parent["valid_from"],
                "parent.valid_from",
            )

            parent_until = _parse_timestamp(
                parent["expires_at"],
                "parent.expires_at",
            )

            child_from = _parse_timestamp(
                grant["valid_from"],
                "child.valid_from",
            )

            child_until = _parse_timestamp(
                grant["expires_at"],
                "child.expires_at",
            )

            if not (parent_from <= child_from < child_until <= parent_until):
                _invalid(
                    "GRANT_EXCEEDS_PARENT_AUTHORITY",
                    "child validity window exceeds parent",
                )

            # Each complete child capability must fit inside one complete
            # parent capability. Mixing action from one parent capability
            # with resource from another is therefore impossible.
            for child_capability in grant["capabilities"]:
                if not any(
                    contains(
                        parent_capability,
                        child_capability,
                    )
                    for parent_capability in parent["capabilities"]
                ):
                    _invalid(
                        "GRANT_EXCEEDS_PARENT_AUTHORITY",
                        f"grant {grant['grant_id']!r} widens capability scope",
                    )

        authority_nodes.append(
            (
                grant["subject_principal"],
                grant["subject_key_id"],
            )
        )

    principals = [principal for principal, _ in authority_nodes]

    key_ids = [key_id for _, key_id in authority_nodes]

    if len(principals) != len(set(principals)) or len(key_ids) != len(set(key_ids)):
        _invalid(
            "CHAIN_DISCONTINUOUS",
            "principal or key cycle detected",
        )

    leaf = chain[-1]
    requested = receipt["requested"]

    if (
        leaf["subject_principal"] != requested["subject_principal"]
        or leaf["subject_key_id"] != requested["subject_key_id"]
    ):
        _invalid(
            "KEY_CONTINUITY_BROKEN",
            "leaf subject does not match requested actor",
        )

    _resolve_key(
        keys,
        leaf["subject_key_id"],
        principal=leaf["subject_principal"],
        usage="subject",
    )

    return cast(str, accountable_principal)


def verify_receipt(
    receipt: Mapping[str, Any],
    trust_bundle: Mapping[str, Any] | None,
    *,
    expected_previous_hash: str | None = None,
    check_previous: bool = False,
) -> VerificationReport:
    """Verify evidence steps 1-7 and conformance steps 8-9."""

    if trust_bundle is None:
        return VerificationReport(
            EvidenceState.UNVERIFIABLE,
            DecisionConformance.NOT_ASSESSABLE,
            "TRUST_BUNDLE_UNAVAILABLE",
            ("no out-of-band trust bundle was supplied",),
        )

    try:
        accountable_principal = _verify_evidence(
            receipt,
            trust_bundle,
            expected_previous_hash=expected_previous_hash,
            check_previous=check_previous,
        )
    except _InvalidEvidenceError as exc:
        return VerificationReport(
            EvidenceState.INVALID,
            DecisionConformance.NOT_ASSESSABLE,
            exc.reason_code,
            (exc.detail,),
        )

    failures: list[str] = []

    # Step 8: independently recompute authority from request and leaf grant.
    expected_authority = evaluate_authority(
        receipt["requested"],
        receipt["grant_chain"][-1],
    )

    if dict(receipt["authority_result"]) != expected_authority:
        failures.append(
            "authority_result does not match independently recomputed authority"
        )

    # Step 9: independently recompute the declared composition profile.
    expected_final = compose_final(
        receipt["authority_result"],
        receipt["policy_result"],
        receipt["composition_profile"],
    )

    if receipt["final_verdict"] != expected_final:
        failures.append(
            "final_verdict contradicts declared composition "
            f"profile (expected {expected_final})"
        )

    return VerificationReport(
        EvidenceState.VERIFIED,
        (
            DecisionConformance.NON_CONFORMANT
            if failures
            else DecisionConformance.CONFORMANT
        ),
        ("DECISION_NON_CONFORMANT" if failures else None),
        tuple(failures),
        accountable_principal,
    )


def verify_receipt_sequence(
    receipts: Sequence[Mapping[str, Any]],
    trust_bundle: Mapping[str, Any] | None,
) -> list[VerificationReport]:
    reports: list[VerificationReport] = []
    previous: Mapping[str, Any] | None = None
    seen_receipt_ids: set[str] = set()
    seen_request_ids: set[str] = set()
    evidence_chain_broken = False

    for receipt in receipts:
        receipt_id = receipt.get("receipt_id")
        request_id = receipt.get("request_id")

        duplicate = (
            isinstance(receipt_id, str) and receipt_id in seen_receipt_ids
        ) or (isinstance(request_id, str) and request_id in seen_request_ids)

        if duplicate:
            report = VerificationReport(
                EvidenceState.INVALID,
                DecisionConformance.NOT_ASSESSABLE,
                "REPLAY_DUPLICATE",
                ("duplicate receipt_id or request_id in supplied sequence",),
            )

        elif evidence_chain_broken:
            report = VerificationReport(
                EvidenceState.INVALID,
                DecisionConformance.NOT_ASSESSABLE,
                "CHAIN_DISCONTINUOUS",
                ("an earlier receipt made the supplied sequence invalid",),
            )

        else:
            report = verify_receipt(
                receipt,
                trust_bundle,
                expected_previous_hash=(
                    receipt_digest(previous) if previous is not None else None
                ),
                check_previous=previous is not None,
            )

        reports.append(report)

        if report.evidence_state is EvidenceState.INVALID:
            evidence_chain_broken = True

        if isinstance(receipt_id, str):
            seen_receipt_ids.add(receipt_id)

        if isinstance(request_id, str):
            seen_request_ids.add(request_id)

        previous = receipt

    return reports


def scan_authority_records(  # noqa: C901
    records: Iterable[Mapping[str, Any]],
    trust_bundle: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Scan receipts or wrapper rows carrying authority_receipt."""

    counts = {state.value: 0 for state in EvidenceState}

    conformance = {state.value: 0 for state in DecisionConformance}

    findings: list[dict[str, Any]] = []
    previous_receipt: Mapping[str, Any] | None = None
    seen_receipt_ids: set[str] = set()
    seen_request_ids: set[str] = set()
    evidence_chain_broken = False

    for index, record in enumerate(records, 1):
        receipt: Any

        if record.get("spec") == RECEIPT_SPEC:
            receipt = record
        else:
            receipt = record.get("authority_receipt")

        if receipt is None:
            counts[EvidenceState.ABSENT.value] += 1
            conformance[DecisionConformance.NOT_ASSESSABLE.value] += 1
            continue

        if not isinstance(receipt, Mapping):
            report = VerificationReport(
                EvidenceState.INVALID,
                DecisionConformance.NOT_ASSESSABLE,
                "SCHEMA_INVALID",
                ("authority_receipt is not an object",),
            )

        else:
            receipt_id = receipt.get("receipt_id")
            request_id = receipt.get("request_id")

            duplicate = (
                isinstance(receipt_id, str) and receipt_id in seen_receipt_ids
            ) or (isinstance(request_id, str) and request_id in seen_request_ids)

            if duplicate:
                report = VerificationReport(
                    EvidenceState.INVALID,
                    DecisionConformance.NOT_ASSESSABLE,
                    "REPLAY_DUPLICATE",
                    ("duplicate receipt_id or request_id in supplied records",),
                )

            elif evidence_chain_broken:
                report = VerificationReport(
                    EvidenceState.INVALID,
                    DecisionConformance.NOT_ASSESSABLE,
                    "CHAIN_DISCONTINUOUS",
                    ("an earlier receipt made the supplied sequence invalid",),
                )

            else:
                report = verify_receipt(
                    receipt,
                    trust_bundle,
                    expected_previous_hash=(
                        receipt_digest(previous_receipt)
                        if previous_receipt is not None
                        else None
                    ),
                    check_previous=previous_receipt is not None,
                )

            if isinstance(receipt_id, str):
                seen_receipt_ids.add(receipt_id)

            if isinstance(request_id, str):
                seen_request_ids.add(request_id)

            previous_receipt = receipt

        if report.evidence_state is EvidenceState.INVALID:
            evidence_chain_broken = True

        counts[report.evidence_state.value] += 1
        conformance[report.decision_conformance.value] += 1

        # This is the scanner's highest-value finding:
        # evidence is authentic, but it does not support the ALLOW.
        if (
            report.evidence_state is EvidenceState.VERIFIED
            and report.decision_conformance is DecisionConformance.NON_CONFORMANT
            and receipt.get("final_verdict") == "ALLOW"
        ):
            findings.append(
                {
                    "row": index,
                    "finding": ("VERIFIED_NON_CONFORMANT_ALLOW"),
                    "accountable_principal": (report.accountable_principal),
                    "failures": list(report.failures),
                }
            )

    total = sum(counts.values())

    return {
        "assessment": "AUTHORISATION READINESS ASSESSMENT",
        "actions_analysed": total,
        "evidence_state": counts,
        "decision_conformance": conformance,
        "critical_findings": findings,
    }
