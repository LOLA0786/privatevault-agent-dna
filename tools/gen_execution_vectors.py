#!/usr/bin/env python3
"""Generate the execution-v01 conformance vectors.

The vectors pin what PrivateVault decides for an execution authorization
(the permit), for the receiver gate's presenter check, and for a dispatch
witness (the evidence of what was sent). Another implementation can be held
to them: a receiver written in another language, the egress gateway running
on a DPU, or hardware logic driven by cocotb.

Every case states its intended outcome here, then runs PrivateVault's own
verifier. Generation fails if the two disagree, so the file records intent
that the code is shown to meet, not whatever the code happens to return.

    uv run python tools/gen_execution_vectors.py           # rewrite the file
    uv run python tools/gen_execution_vectors.py --check   # exit 1 if stale
"""

from __future__ import annotations

import argparse
import base64
import copy
import datetime as dt
import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from nacl.signing import SigningKey

from agent_dna.action_v01 import execution_action_digest
from agent_dna.authority_v01 import (
    CANONICALIZATION,
    TRUST_SPEC,
    DecisionConformance,
    EvidenceState,
    canonicalize,
    encode_public_key,
    sha256_digest,
    sign_document,
)
from agent_dna.dispatch_v01 import create_dispatch_witness, verify_dispatch_witness
from agent_dna.execution_v01 import (
    EXECUTION_AUTHORIZATION_SPEC,
    EXECUTION_AUTHORIZATION_SPEC_V02,
    execution_authorization_digest,
    sha256_bytes_digest,
    sign_execution_authorization,
    verify_execution_authorization,
)
from agent_dna.presenter_identity import presenter_identity_digest
from agent_dna.receiver.gate import ReceiverGate, _RefusalError
from agent_dna.wire_serialization_v01 import (
    WIRE_SERIALIZATION_JSON_PARAMETERS_V01,
    serialize_parameters_wire,
    wire_action_binding_reason,
)

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "spec" / "execution-v01" / "vectors" / "execution-v01.json"
VECTORS_SPEC = "pv-execution-vectors/1"
ORG = "org-vectors"

VERIFIED, INVALID, UNVERIFIABLE = (
    EvidenceState.VERIFIED,
    EvidenceState.INVALID,
    EvidenceState.UNVERIFIABLE,
)
CONFORMANT, NON_CONFORMANT, NOT_ASSESSABLE = (
    DecisionConformance.CONFORMANT,
    DecisionConformance.NON_CONFORMANT,
    DecisionConformance.NOT_ASSESSABLE,
)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def _seed(label: str) -> bytes:
    """A fixed 32-byte seed per label: the same keys on every run."""
    return hashlib.sha256(f"{VECTORS_SPEC} {label}".encode()).digest()


def _label_digest(label: str) -> str:
    return sha256_digest({"vector": label})


KEY_LABELS = {
    "exec-1": "execution-authorization-signer",
    "witness-1": "dispatch-witness-signer",
    "stranger-1": "key-not-in-any-trust-bundle",
}
KEYS = {key_id: SigningKey(_seed(label)) for key_id, label in KEY_LABELS.items()}


def _ed25519_certificate(label: str) -> tuple[bytes, bytes]:
    """A deterministic self-signed Ed25519 certificate and its DER SPKI."""
    key = Ed25519PrivateKey.from_private_bytes(_seed(label))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])
    start = dt.datetime(2026, 11, 1, tzinfo=dt.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(int.from_bytes(_seed(label)[:8], "big") >> 1 or 1)
        .not_valid_before(start)
        .not_valid_after(start + dt.timedelta(days=365))
        .sign(key, algorithm=None)
    )
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return certificate.public_bytes(serialization.Encoding.DER), spki


PRESENTER_CERT, PRESENTER_SPKI = _ed25519_certificate("refunds-agent sidecar")
OTHER_CERT, _ = _ed25519_certificate("some other process")
_, PEER = _ed25519_certificate("payments.example server")
_, OTHER_PEER = _ed25519_certificate("look-alike server")

ACTION = {
    "subject_principal": f"refunds-agent@{ORG}",
    "subject_key_id": "refunds-agent",
    "action": "payments.refund.issue",
    "resource": "orders:ORD-70340",
    "parameters": {
        "amount": 3000,
        "currency": "INR",
        "order_id": "ORD-70340",
        "payee": "kavya.n@okaxis",
    },
}
# The permit's bytes are derived from the action, never typed: authorize
# re-derives them under the named serialization and refuses a mismatch.
WIRE = serialize_parameters_wire(
    ACTION["parameters"], serialization=WIRE_SERIALIZATION_JSON_PARAMETERS_V01
)
WIRE_SAME_LENGTH = WIRE.replace(b'"amount":3000', b'"amount":9000')
WIRE_LONGER = WIRE.replace(b'"amount":3000', b'"amount":30000')
DISPATCH = {
    "transport": "https",
    "destination": "payments.example",
    "operation": "POST /v1/refunds",
    "wire_content_type": "application/json",
    "wire_content_encoding": "identity",
    "tool_id": "payments.refund.issue.v1",
    "tool_schema_digest": _label_digest("tool schema"),
    "tool_artifact_digest": _label_digest("tool artifact"),
    "credential_audience": "payments.example",
    "idempotency_key_digest": _label_digest("idempotency key ORD-70340"),
    "retry_policy_digest": _label_digest("retry policy: never"),
    "serialization": WIRE_SERIALIZATION_JSON_PARAMETERS_V01,
}
BINDINGS = {
    "decision_receipt_digest": _label_digest("decision receipt"),
    "authority_receipt_digest": _label_digest("authority receipt"),
    "approval_artifact_digest": None,
    "state_snapshot_digest": _label_digest("state snapshot"),
    "policy_bundle_digest": _label_digest("policy bundle"),
    "obligations_digest": _label_digest("obligations"),
}
REQUEST_ID = "req-ORD-70340-refund"
ISSUED, EXPIRES = "2026-11-25T10:00:00Z", "2026-11-25T10:01:00Z"
AT, BEFORE = "2026-11-25T10:00:30Z", "2026-11-25T09:59:59Z"


def _trust_bundle(*, organisation: str = ORG, version: int = 1) -> dict[str, Any]:
    return {
        "spec": TRUST_SPEC,
        "canonicalization": CANONICALIZATION,
        "organisation_id": organisation,
        "bundle_version": version,
        "pinned_at": "2026-11-01T00:00:00Z",
        "keys": [
            {
                "key_id": "exec-1",
                "principal": f"execution-runtime@{organisation}",
                "algorithm": "ed25519",
                "public_key": encode_public_key(KEYS["exec-1"]),
                "usages": ["execution_authorization_signer"],
            },
            {
                "key_id": "witness-1",
                "principal": f"egress-sidecar@{organisation}",
                "algorithm": "ed25519",
                "public_key": encode_public_key(KEYS["witness-1"]),
                "usages": ["dispatch_witness_signer"],
            },
        ],
    }


TRUST_BUNDLES = {
    "default": _trust_bundle(),
    "rotated": _trust_bundle(version=2),
    "other-organisation": _trust_bundle(organisation="org-elsewhere"),
}


def _unsigned(
    *, spec: str = EXECUTION_AUTHORIZATION_SPEC, **overrides: Any
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "spec": spec,
        "canonicalization": CANONICALIZATION,
        "execution_authorization_id": "ea-vectors-0001",
        "organisation_id": ORG,
        "request_id": REQUEST_ID,
        "issued_at": ISSUED,
        "not_before": ISSUED,
        "expires_at": EXPIRES,
        "nonce": "n-7f3a9c1e5b2d4f60",
        **BINDINGS,
        "action": copy.deepcopy(ACTION),
        "action_digest": execution_action_digest(ACTION),
        "expected_wire_bytes_digest": sha256_bytes_digest(WIRE),
        "expected_wire_bytes_length": len(WIRE),
        "expected_peer_identity_digest": sha256_bytes_digest(PEER),
        "dispatch": copy.deepcopy(DISPATCH),
        "trust_bundle_digest": sha256_digest(TRUST_BUNDLES["default"]),
        "max_uses": 1,
        "signer_key_id": "exec-1",
    }
    if spec == EXECUTION_AUTHORIZATION_SPEC_V02:
        document["expected_presenter_identity_digest"] = (
            "sha256:" + hashlib.sha256(PRESENTER_SPKI).hexdigest()
        )
    document.update(overrides)
    return document


def _signed(*, key_id: str = "exec-1", **overrides: Any) -> dict[str, Any]:
    return sign_execution_authorization(
        _unsigned(signer_key_id=key_id, **overrides), KEYS[key_id]
    )


V01 = _signed()
V02 = _signed(spec=EXECUTION_AUTHORIZATION_SPEC_V02)


def _context(**overrides: Any) -> dict[str, Any]:
    context: dict[str, Any] = {
        "expected_request_id": REQUEST_ID,
        "expected_action": copy.deepcopy(ACTION),
        "expected_dispatch": copy.deepcopy(DISPATCH),
        **{f"expected_{name}": value for name, value in BINDINGS.items()},
        "expected_wire_bytes_b64": b64(WIRE),
        "expected_peer_identity_b64": b64(PEER),
        "at_time": AT,
        "already_consumed": False,
        "ledger_already_holds_id": False,
    }
    context.update(overrides)
    return context


def _expect(
    state: EvidenceState,
    conformance: DecisionConformance,
    reason: str | None,
    *failures: str,
) -> dict[str, Any]:
    return {
        "evidence_state": state.value,
        "decision_conformance": conformance.value,
        "reason_code": reason,
        "failures": list(failures),
    }


def _ok() -> dict[str, Any]:
    return _expect(VERIFIED, CONFORMANT, None)


def _off(*failures: str) -> dict[str, Any]:
    return _expect(
        VERIFIED, NON_CONFORMANT, "EXECUTION_AUTHORIZATION_NON_CONFORMANT", *failures
    )


BYTES = "authorization does not bind the intended outbound bytes"
LENGTH = "authorization does not bind the intended outbound byte length"
PEER_FAIL = "authorization does not bind the intended peer identity"
TIME = "execution authorization is not valid at dispatch time"

_ACTION_CHANGED = copy.deepcopy(ACTION)
_ACTION_CHANGED["parameters"]["amount"] = 9000
_DISPATCH_CHANGED = {**DISPATCH, "destination": "payments.attacker.example"}
_EXTENDED = dict(V01, expires_at="2026-11-25T11:00:00Z")
_TOO_MANY_USES = sign_document(
    _unsigned(max_uses=2), KEYS["exec-1"], signature_field="signature"
)

AUTHORIZATION_CASES: list[tuple[str, str, dict, str | None, dict, dict]] = [
    (
        "EA-01",
        "A valid 0.1 permit, presented with exactly its bytes, peer and window",
        V01,
        "default",
        _context(),
        _ok(),
    ),
    (
        "EA-02",
        "A valid 0.2 permit; the presenter is checked by the receiver gate (PR cases)",
        V02,
        "default",
        _context(),
        _ok(),
    ),
    (
        "EA-03",
        "One byte of the body changed, same length",
        V01,
        "default",
        _context(expected_wire_bytes_b64=b64(WIRE_SAME_LENGTH)),
        _off(BYTES),
    ),
    (
        "EA-04",
        "The body changed length",
        V01,
        "default",
        _context(expected_wire_bytes_b64=b64(WIRE_LONGER)),
        _off(BYTES, LENGTH),
    ),
    (
        "EA-05",
        "Sent to a different TLS peer",
        V01,
        "default",
        _context(expected_peer_identity_b64=b64(OTHER_PEER)),
        _off(PEER_FAIL),
    ),
    (
        "EA-06",
        "The action differs from the one the permit names",
        V01,
        "default",
        _context(expected_action=_ACTION_CHANGED),
        _off(
            "authorization action_digest does not match the observed action",
            "authorization action does not exactly match the observed action",
        ),
    ),
    (
        "EA-07",
        "The dispatch goes to another destination",
        V01,
        "default",
        _context(expected_dispatch=_DISPATCH_CHANGED),
        _off("authorization dispatch does not exactly match the observed dispatch"),
    ),
    (
        "EA-08",
        "Presented for a different request",
        V01,
        "default",
        _context(expected_request_id="req-someone-else"),
        _off("authorization request_id does not match the execution request"),
    ),
    (
        "EA-09",
        "Presented one second before not_before",
        V01,
        "default",
        _context(at_time=BEFORE),
        _off(TIME),
    ),
    (
        "EA-10",
        "Presented exactly at expires_at (the window excludes it)",
        V01,
        "default",
        _context(at_time=EXPIRES),
        _off(TIME),
    ),
    (
        "EA-11",
        "The caller already knows the permit was used",
        V01,
        "default",
        _context(already_consumed=True),
        _expect(
            VERIFIED,
            NON_CONFORMANT,
            "EXECUTION_AUTHORIZATION_CONSUMED",
            "execution authorization has already been consumed",
        ),
    ),
    (
        "EA-12",
        "Second use: the durable ledger already holds this permit id",
        V01,
        "default",
        _context(ledger_already_holds_id=True),
        _expect(
            VERIFIED,
            NON_CONFORMANT,
            "EXECUTION_AUTHORIZATION_CONSUMED",
            "execution authorization has already been consumed",
        ),
    ),
    (
        "EA-13",
        "expires_at extended after signing",
        _EXTENDED,
        "default",
        _context(),
        _expect(
            INVALID,
            NOT_ASSESSABLE,
            "EXECUTION_AUTHORIZATION_SIGNATURE_INVALID",
            "execution authorization signature is invalid",
        ),
    ),
    (
        "EA-14",
        "Signed by a key the trust bundle does not hold",
        _signed(key_id="stranger-1"),
        "default",
        _context(),
        _expect(
            INVALID,
            NOT_ASSESSABLE,
            "TRUST_ROOT_UNKNOWN",
            "execution signer key 'stranger-1' is absent from trust bundle",
        ),
    ),
    (
        "EA-15",
        "Signed by the witness key, which may not sign permits",
        _signed(key_id="witness-1"),
        "default",
        _context(),
        _expect(
            INVALID,
            NOT_ASSESSABLE,
            "KEY_USAGE_INVALID",
            "key 'witness-1' lacks required usage 'execution_authorization_signer'",
        ),
    ),
    (
        "EA-16",
        "Verified against a rotated trust bundle it does not bind",
        V01,
        "rotated",
        _context(),
        _expect(
            INVALID,
            NOT_ASSESSABLE,
            "TRUST_BUNDLE_DIGEST_MISMATCH",
            "authorization does not bind the supplied trust bundle",
        ),
    ),
    (
        "EA-17",
        "Verified against another organisation's trust bundle",
        V01,
        "other-organisation",
        _context(),
        _expect(
            INVALID,
            NOT_ASSESSABLE,
            "ORGANISATION_MISMATCH",
            "authorization and trust bundle organisations differ",
        ),
    ),
    (
        "EA-18",
        "Signed, but allows two uses",
        _TOO_MANY_USES,
        "default",
        _context(),
        _expect(
            INVALID,
            NOT_ASSESSABLE,
            "SCHEMA_INVALID",
            "execution_authorization.max_uses: expected integer 1",
        ),
    ),
    (
        "EA-19",
        "No trust bundle supplied",
        V01,
        None,
        _context(),
        _expect(
            UNVERIFIABLE,
            NOT_ASSESSABLE,
            "TRUST_BUNDLE_UNAVAILABLE",
            "no out-of-band trust bundle was supplied",
        ),
    ),
]

PRESENTER_CASES: list[tuple[str, str, str, bool, bytes | None, dict]] = [
    (
        "PR-01",
        "0.2 permit over mTLS with the key it names",
        "EA-02",
        True,
        PRESENTER_CERT,
        {"admitted": True, "reason_code": None},
    ),
    (
        "PR-02",
        "0.2 permit over mTLS with another key",
        "EA-02",
        True,
        OTHER_CERT,
        {"admitted": False, "reason_code": "RECEIVER_PRESENTER_MISMATCH"},
    ),
    (
        "PR-03",
        "0.2 permit with no client certificate",
        "EA-02",
        True,
        None,
        {"admitted": False, "reason_code": "RECEIVER_PRESENTER_MISSING"},
    ),
    (
        "PR-04",
        "0.2 permit with bytes that are not a certificate",
        "EA-02",
        True,
        b"not a certificate",
        {"admitted": False, "reason_code": "RECEIVER_PRESENTER_MISMATCH"},
    ),
    (
        "PR-05",
        "0.1 permit at a gate that requires a presenter",
        "EA-01",
        True,
        PRESENTER_CERT,
        {"admitted": False, "reason_code": "RECEIVER_PRESENTER_REQUIRED"},
    ),
    (
        "PR-06",
        "0.1 permit at a gate that does not require one",
        "EA-01",
        False,
        None,
        {"admitted": True, "reason_code": None},
    ),
]

_WITNESS_METADATA = {
    "dispatch_witness_id": "dw-vectors-0001",
    "observed_at": "2026-11-25T10:00:31Z",
    "attempt": 1,
    "witness_component_id": "egress-sidecar-1",
    "wire_content_type": "application/json",
    "wire_content_encoding": "identity",
    "signer_key_id": "witness-1",
}


def _witness(
    *,
    wire: bytes = WIRE,
    peer: bytes = PEER,
    key_id: str = "witness-1",
    **metadata: Any,
) -> dict[str, Any]:
    return create_dispatch_witness(
        {**_WITNESS_METADATA, "signer_key_id": key_id, **metadata},
        authorization=V01,
        trust_bundle=TRUST_BUNDLES["default"],
        observed_action=ACTION,
        observed_dispatch=DISPATCH,
        wire_bytes=wire,
        peer_identity_bytes=peer,
        signing_key=KEYS[key_id],
    )


def _w_off(*failures: str) -> dict[str, Any]:
    return _expect(VERIFIED, NON_CONFORMANT, "DISPATCH_NON_CONFORMANT", *failures)


_W_VALID = _witness()
WITNESS_CASES: list[tuple[str, str, dict, bytes, bytes, dict]] = [
    (
        "DW-01",
        "The sidecar sent exactly the permitted bytes to the permitted peer",
        _W_VALID,
        WIRE,
        PEER,
        _ok(),
    ),
    (
        "DW-02",
        "The sidecar honestly witnesses different bytes",
        _witness(wire=WIRE_SAME_LENGTH),
        WIRE_SAME_LENGTH,
        PEER,
        _w_off(
            "observed outbound bytes are not the exact bytes authorized by the permit"
        ),
    ),
    (
        "DW-03",
        "The witness claims the permitted bytes; different bytes were observed",
        _W_VALID,
        WIRE_SAME_LENGTH,
        PEER,
        _w_off(
            "dispatch witness wire digest does not match the observed outbound bytes",
            "observed outbound bytes are not the exact bytes authorized by the permit",
        ),
    ),
    (
        "DW-04",
        "A retry: attempt 2 of a single-use permit",
        _witness(attempt=2),
        WIRE,
        PEER,
        _w_off("single-use authorization cannot witness a retry attempt"),
    ),
    (
        "DW-05",
        "Sent at expires_at, outside the permit's window",
        _witness(observed_at=EXPIRES),
        WIRE,
        PEER,
        _w_off("dispatch occurred outside the authorization validity window"),
    ),
    (
        "DW-06",
        "Sent to a different TLS peer",
        _witness(peer=OTHER_PEER),
        WIRE,
        OTHER_PEER,
        _w_off("observed peer identity is not the peer authorized by the permit"),
    ),
    (
        "DW-07",
        "Witness signed by the permit key, which may not sign witnesses",
        _witness(key_id="exec-1"),
        WIRE,
        PEER,
        _expect(
            INVALID,
            NOT_ASSESSABLE,
            "WITNESS_KEY_USAGE_INVALID",
            "key 'exec-1' lacks required usage 'dispatch_witness_signer'",
        ),
    ),
    (
        "DW-08",
        "observed_at moved earlier after signing",
        dict(_W_VALID, observed_at="2026-11-25T10:00:01Z"),
        WIRE,
        PEER,
        _expect(
            INVALID,
            NOT_ASSESSABLE,
            "DISPATCH_WITNESS_SIGNATURE_INVALID",
            "dispatch witness signature is invalid",
        ),
    ),
]


# Authorize-time binding (ADR 0017): the permit's byte digest must be exactly
# the named serialization of its action's parameters, so nobody can bind an
# action to one hash and the bytes to another.
WIRE_BINDING_CASES: list[tuple[str, str, Any, str, int, str | None]] = [
    (
        "WB-01",
        "Digest and length of the action's own serialization",
        WIRE_SERIALIZATION_JSON_PARAMETERS_V01,
        sha256_bytes_digest(WIRE),
        len(WIRE),
        None,
    ),
    (
        "WB-02",
        "Digest of other bytes of the same length",
        WIRE_SERIALIZATION_JSON_PARAMETERS_V01,
        sha256_bytes_digest(WIRE_SAME_LENGTH),
        len(WIRE),
        "AUTHORIZE_WIRE_ACTION_MISMATCH",
    ),
    (
        "WB-03",
        "Right digest, wrong length",
        WIRE_SERIALIZATION_JSON_PARAMETERS_V01,
        sha256_bytes_digest(WIRE),
        len(WIRE) + 1,
        "AUTHORIZE_WIRE_ACTION_MISMATCH",
    ),
    (
        "WB-04",
        "A serialization the verifier does not know",
        "pv-json-parameters/9.9",
        sha256_bytes_digest(WIRE),
        len(WIRE),
        "AUTHORIZE_WIRE_SERIALIZATION_UNKNOWN",
    ),
    (
        "WB-05",
        "No serialization named",
        None,
        sha256_bytes_digest(WIRE),
        len(WIRE),
        "AUTHORIZE_WIRE_SERIALIZATION_REQUIRED",
    ),
]


def run_wire_binding(
    action: dict, serialization: Any, digest: str, length: int
) -> dict[str, Any]:
    """Replay one wire-binding case through authorize's own check."""
    return {
        "reason_code": wire_action_binding_reason(
            action=action,
            serialization=serialization,
            expected_wire_bytes_digest=digest,
            expected_wire_bytes_length=length,
        )
    }


class _Ledger:
    """The smallest durable-ledger stand-in: a set of claimed permit ids."""

    def __init__(self, held: set[tuple[str, str]]) -> None:
        self.held = held

    def try_consume_execution_authorization(
        self, authorization_id: str, *, organisation_id: str, consumed_at: str
    ) -> bool:
        key = (organisation_id, authorization_id)
        if key in self.held:
            return False
        self.held.add(key)
        return True


def _report(report: Any) -> dict[str, Any]:
    return {
        "evidence_state": report.evidence_state.value,
        "decision_conformance": report.decision_conformance.value,
        "reason_code": report.reason_code,
        "failures": list(report.failures),
        "accountable_principal": report.accountable_principal,
    }


def run_authorization(
    authorization: dict, trust_bundle: dict | None, context: dict
) -> dict[str, Any]:
    """Replay one authorization case through PrivateVault's verifier."""
    held = set()
    if context["ledger_already_holds_id"]:
        held.add(
            (
                authorization["organisation_id"],
                authorization["execution_authorization_id"],
            )
        )
    return _report(
        verify_execution_authorization(
            authorization,
            trust_bundle,
            expected_request_id=context["expected_request_id"],
            expected_action=context["expected_action"],
            expected_dispatch=context["expected_dispatch"],
            expected_decision_receipt_digest=context[
                "expected_decision_receipt_digest"
            ],
            expected_authority_receipt_digest=context[
                "expected_authority_receipt_digest"
            ],
            expected_approval_artifact_digest=context[
                "expected_approval_artifact_digest"
            ],
            expected_state_snapshot_digest=context["expected_state_snapshot_digest"],
            expected_policy_bundle_digest=context["expected_policy_bundle_digest"],
            expected_obligations_digest=context["expected_obligations_digest"],
            expected_wire_bytes=unb64(context["expected_wire_bytes_b64"]),
            expected_peer_identity_bytes=unb64(context["expected_peer_identity_b64"]),
            at_time=context["at_time"],
            already_consumed=context["already_consumed"],
            consume_ledger=_Ledger(held),
        )
    )


def run_presenter(
    authorization: dict, gate_requires_presenter: bool, certificate: bytes | None
) -> dict[str, Any]:
    """Replay one presenter case through the receiver gate's own check."""
    gate = SimpleNamespace(require_presenter=gate_requires_presenter)
    try:
        ReceiverGate._verify_presenter(gate, authorization, certificate)  # type: ignore[arg-type]
    except _RefusalError as exc:
        return {"admitted": False, "reason_code": exc.reason_code}
    return {"admitted": True, "reason_code": None}


def run_witness(
    witness: dict, authorization: dict, trust_bundle: dict, wire: bytes, peer: bytes
) -> dict[str, Any]:
    """Replay one witness case through PrivateVault's verifier."""
    return _report(
        verify_dispatch_witness(
            witness,
            authorization,
            trust_bundle,
            observed_action=ACTION,
            observed_dispatch=DISPATCH,
            wire_bytes=wire,
            peer_identity_bytes=peer,
        )
    )


def _matches(intended: dict[str, Any], actual: dict[str, Any]) -> bool:
    return all(actual.get(key) == value for key, value in intended.items())


def build() -> dict[str, Any]:
    """Build the vectors, failing loudly where intent and code disagree."""
    by_id: dict[str, dict] = {}
    disagreements: list[str] = []

    authorization_cases = []
    for (
        case_id,
        title,
        authorization,
        bundle_name,
        context,
        intended,
    ) in AUTHORIZATION_CASES:
        bundle = TRUST_BUNDLES[bundle_name] if bundle_name else None
        actual = run_authorization(authorization, bundle, context)
        if not _matches(intended, actual):
            disagreements.append(
                f"{case_id}: intended {intended}, verifier said {actual}"
            )
        by_id[case_id] = authorization
        authorization_cases.append(
            {
                "id": case_id,
                "title": title,
                "authorization": authorization,
                "trust_bundle": bundle_name,
                "context": context,
                "expect": actual,
            }
        )

    presenter_cases = []
    for case_id, title, ref, required, certificate, intended in PRESENTER_CASES:
        actual = run_presenter(by_id[ref], required, certificate)
        if actual != intended:
            disagreements.append(f"{case_id}: intended {intended}, gate said {actual}")
        presenter_cases.append(
            {
                "id": case_id,
                "title": title,
                "authorization_case": ref,
                "gate_requires_presenter": required,
                "client_certificate_der_b64": b64(certificate)
                if certificate is not None
                else None,
                "expect": actual,
            }
        )

    witness_cases = []
    for case_id, title, witness, wire, peer, intended in WITNESS_CASES:
        actual = run_witness(witness, V01, TRUST_BUNDLES["default"], wire, peer)
        if not _matches(intended, actual):
            disagreements.append(
                f"{case_id}: intended {intended}, verifier said {actual}"
            )
        witness_cases.append(
            {
                "id": case_id,
                "title": title,
                "witness": witness,
                "authorization_case": "EA-01",
                "trust_bundle": "default",
                "observed": {
                    "action": ACTION,
                    "dispatch": DISPATCH,
                    "wire_bytes_b64": b64(wire),
                    "peer_identity_b64": b64(peer),
                },
                "expect": actual,
            }
        )

    wire_binding_cases = []
    for (
        case_id,
        title,
        serialization_name,
        digest,
        length,
        intended_reason,
    ) in WIRE_BINDING_CASES:
        actual = run_wire_binding(ACTION, serialization_name, digest, length)
        if actual != {"reason_code": intended_reason}:
            disagreements.append(
                f"{case_id}: intended {intended_reason}, authorize said {actual}"
            )
        wire_binding_cases.append(
            {
                "id": case_id,
                "title": title,
                "action": ACTION,
                "serialization": serialization_name,
                "expected_wire_bytes_digest": digest,
                "expected_wire_bytes_length": length,
                "expect": actual,
            }
        )

    if disagreements:
        raise SystemExit(
            "intent and verifier disagree:\n  " + "\n  ".join(disagreements)
        )

    unsigned_v01 = {key: value for key, value in V01.items() if key != "signature"}
    return {
        "spec": VECTORS_SPEC,
        "generated_by": "tools/gen_execution_vectors.py",
        "covers": [
            EXECUTION_AUTHORIZATION_SPEC,
            EXECUTION_AUTHORIZATION_SPEC_V02,
            "pv-dispatch-witness/0.1-experimental",
        ],
        "canonicalization": CANONICALIZATION,
        "signature_format": "ed25519:<base64 of the 64-byte Ed25519 signature over the RFC 8785 bytes of the document without its signature field>",
        "wire_serializations": {
            WIRE_SERIALIZATION_JSON_PARAMETERS_V01: "UTF-8 JSON of action.parameters: keys sorted by code point, no whitespace, non-ASCII unescaped, NaN and Infinity refused",
        },
        "seed_derivation": f"test-only Ed25519 seed = SHA-256 of the UTF-8 text '{VECTORS_SPEC} ' followed by seed_label",
        "keys": {
            key_id: {
                "public_key": encode_public_key(key),
                "seed_label": KEY_LABELS[key_id],
            }
            for key_id, key in KEYS.items()
        },
        "trust_bundles": TRUST_BUNDLES,
        "fixtures": {
            "action": ACTION,
            "dispatch": DISPATCH,
            "wire_bytes_b64": b64(WIRE),
            "peer_identity_b64": b64(PEER),
            "presenter_certificate_der_b64": b64(PRESENTER_CERT),
            "presenter_spki_der_b64": b64(PRESENTER_SPKI),
            "presenter_identity_digest": presenter_identity_digest(PRESENTER_CERT),
            "ea01_signing_input_b64": b64(canonicalize(unsigned_v01)),
            "ea01_authorization_digest": execution_authorization_digest(V01),
        },
        "authorization_cases": authorization_cases,
        "presenter_cases": presenter_cases,
        "witness_cases": witness_cases,
        "wire_binding_cases": wire_binding_cases,
    }


def render() -> str:
    return json.dumps(build(), indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--check", action="store_true", help="exit 1 if the committed file is stale"
    )
    args = parser.parse_args(argv)
    text = render()
    if args.check:
        current = OUT.read_text(encoding="utf-8") if OUT.exists() else ""
        if current != text:
            print(
                f"{OUT.relative_to(ROOT)} is stale: run tools/gen_execution_vectors.py",
                file=sys.stderr,
            )
            return 1
        print(f"{OUT.relative_to(ROOT)} is current")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    vectors = json.loads(text)
    print(
        f"wrote {OUT.relative_to(ROOT)}: {len(vectors['authorization_cases'])} authorization, "
        f"{len(vectors['presenter_cases'])} presenter, {len(vectors['witness_cases'])} witness, "
        f"{len(vectors['wire_binding_cases'])} wire-binding cases"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
