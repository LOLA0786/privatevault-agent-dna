"""KMS stand-ins backed by a real Ed25519 key, for tests without cloud access.

``FakeAwsKms`` validates every request (and its own responses) against
AWS's published KMS API model, shipped in botocore: parameter names, types,
enum values and size limits are AWS's, not ours. What it cannot show is a
live AWS endpoint; ``tools/kms_smoke.py`` does that against a real key.

``FakeGcpKms`` mirrors Cloud KMS's ``get_public_key`` / ``asymmetric_sign``
response fields, including the CRC32C integrity fields.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from nacl.signing import SigningKey

from agent_dna.key_custody import crc32c

SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def spki(key: SigningKey) -> bytes:
    return SPKI_PREFIX + bytes(key.verify_key)


@dataclass
class FakeAwsKms:
    key: SigningKey = field(default_factory=SigningKey.generate)
    key_id: str = (
        "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    )
    key_spec: str = "ECC_NIST_EDWARDS25519"
    fail_sign: bool = False
    tamper: bool = False
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)

    def _check(
        self, operation: str, params: dict[str, Any], response: dict[str, Any]
    ) -> None:
        import botocore.session
        from botocore.validate import ParamValidator

        model = botocore.session.get_session().get_service_model("kms")
        op = model.operation_model(operation)
        report = ParamValidator().validate(params, op.input_shape)
        if report.has_errors():
            raise AssertionError(
                f"{operation} request breaks the AWS model:\n{report.generate_report()}"
            )
        out = ParamValidator().validate(response, op.output_shape)
        if out.has_errors():
            raise AssertionError(f"fake {operation} response breaks the AWS model")
        self.calls.append((operation, params))

    def get_public_key(self, **params: Any) -> dict[str, Any]:
        response = {
            "KeyId": self.key_id,
            "PublicKey": spki(self.key),
            "KeySpec": self.key_spec,
            "KeyUsage": "SIGN_VERIFY",
            "SigningAlgorithms": ["ED25519_SHA_512", "ED25519_PH_SHA_512"],
        }
        self._check("GetPublicKey", params, response)
        return response

    def sign(self, **params: Any) -> dict[str, Any]:
        if self.fail_sign:
            raise ConnectionError("KMS endpoint unreachable")
        message = params["Message"]
        if self.tamper:
            message = message + b"!"
        response = {
            "KeyId": self.key_id,
            "Signature": bytes(self.key.sign(message).signature),
            "SigningAlgorithm": params["SigningAlgorithm"],
        }
        self._check("Sign", params, response)
        return response


class _Algorithm(Enum):
    EC_SIGN_ED25519 = 27
    EC_SIGN_P256_SHA256 = 12


@dataclass
class _PublicKey:
    pem: str
    algorithm: _Algorithm
    pem_crc32c: int
    name: str


@dataclass
class _SignResponse:
    signature: bytes
    signature_crc32c: int
    verified_data_crc32c: bool
    name: str


@dataclass
class FakeGcpKms:
    key: SigningKey = field(default_factory=SigningKey.generate)
    name: str = (
        "projects/p/locations/global/keyRings/pv/cryptoKeys/exec/cryptoKeyVersions/1"
    )
    algorithm: _Algorithm = _Algorithm.EC_SIGN_ED25519
    corrupt_signature_crc: bool = False
    skip_data_check: bool = False

    def get_public_key(self, request: dict[str, Any]) -> _PublicKey:
        assert set(request) == {"name"}
        b64 = base64.b64encode(spki(self.key)).decode()
        pem = f"-----BEGIN PUBLIC KEY-----\n{b64}\n-----END PUBLIC KEY-----\n"
        return _PublicKey(pem, self.algorithm, crc32c(pem.encode()), request["name"])

    def asymmetric_sign(self, request: dict[str, Any]) -> _SignResponse:
        assert set(request) == {"name", "data", "data_crc32c"}
        data = request["data"]
        verified = not self.skip_data_check and request["data_crc32c"] == crc32c(data)
        signature = bytes(self.key.sign(data).signature)
        crc = crc32c(signature) ^ (1 if self.corrupt_signature_crc else 0)
        return _SignResponse(signature, crc, verified, request["name"])
