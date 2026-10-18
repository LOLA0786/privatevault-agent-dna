"""Where PrivateVault's Ed25519 signing keys live: local or in a KMS.

Every signature PrivateVault produces is pure Ed25519 (RFC 8032), verified
by anyone holding the public key, so the private key can live in a cloud
KMS without changing any verifier. A key setting names its custody:

    PV_EXECUTION_SIGNER_KEY=/run/keys/exec.key          local 32-byte seed file
    PV_EXECUTION_SIGNER_KEY=awskms:arn:aws:kms:...:key/...  AWS KMS
    PV_EXECUTION_SIGNER_KEY=gcpkms:projects/.../cryptoKeyVersions/1  Cloud KMS

``PV_RECEIPT_SIGNING_KEY`` keeps its 64-hex seed form and takes the same
``awskms:`` / ``gcpkms:`` references; so do the dispatch witness key and the
receiver kit's receipt key.

KMS requirements (checked when the signer is built, before serving):

* AWS: key spec ``ECC_NIST_EDWARDS25519``, usage ``SIGN_VERIFY``, signing
  with ``ED25519_SHA_512`` and ``MessageType=RAW`` (pure Ed25519). AWS signs
  at most 4096 bytes RAW; a larger document is refused, never pre-hashed
  (``ED25519_PH_SHA_512`` is a different signature that verifiers would
  reject).
* Google Cloud: a key version with algorithm ``EC_SIGN_ED25519``; requests
  and responses carry CRC32C checksums, which are checked.

Every signature returned by a KMS is verified locally against the key's
public key before it is used, so a misconfigured key, algorithm or proxy
fails closed instead of producing permits that receivers would reject.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

AWS_PREFIX = "awskms:"
GCP_PREFIX = "gcpkms:"
AWS_MAX_RAW_MESSAGE = 4096
# DER SubjectPublicKeyInfo of an Ed25519 key: fixed 12-byte header + 32 bytes.
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


class SignerError(RuntimeError):
    """The signing key could not be used. Callers fail closed."""


@runtime_checkable
class Ed25519Signer(Protocol):
    """A pure-Ed25519 signer whose private key may live outside the process."""

    @property
    def public_key(self) -> bytes:
        """The raw 32-byte public key."""

    @property
    def description(self) -> str:
        """Where the key lives, safe to log (no secret material)."""

    def sign(self, message: bytes) -> bytes:
        """The raw 64-byte RFC 8032 signature of ``message``."""


def _verified(public_key: bytes, message: bytes, signature: bytes, where: str) -> bytes:
    if len(signature) != 64:
        raise SignerError(
            f"{where} returned a {len(signature)}-byte signature, not Ed25519"
        )
    try:
        VerifyKey(public_key).verify(message, signature)
    except BadSignatureError as exc:
        raise SignerError(
            f"{where} returned a signature that does not verify under its own "
            "public key (wrong algorithm, key, or message type?)"
        ) from exc
    return signature


def ed25519_public_key_from_spki(der: bytes) -> bytes:
    if len(der) != 44 or not der.startswith(_ED25519_SPKI_PREFIX):
        raise SignerError("public key is not an Ed25519 SubjectPublicKeyInfo")
    return der[12:]


def _pem_to_der(pem: str) -> bytes:
    lines = [line.strip() for line in pem.strip().splitlines()]
    if not lines or not lines[0].startswith("-----BEGIN PUBLIC KEY"):
        raise SignerError("public key PEM expected")
    return base64.b64decode(
        "".join(line for line in lines if not line.startswith("-----"))
    )


class LocalSigner:
    """A key held in this process (a seed file or environment variable)."""

    def __init__(self, signing_key: SigningKey, description: str = "local key") -> None:
        self._key = signing_key
        self._public = bytes(signing_key.verify_key)
        self._description = description

    @property
    def public_key(self) -> bytes:
        return self._public

    @property
    def description(self) -> str:
        return self._description

    def sign(self, message: bytes) -> bytes:
        return bytes(self._key.sign(bytes(message)).signature)


class AwsKmsSigner:
    """Ed25519 in AWS KMS (``ECC_NIST_EDWARDS25519``, ``ED25519_SHA_512``)."""

    def __init__(self, key_id: str, client: Any = None) -> None:
        if not key_id:
            raise SignerError("AWS KMS key id or ARN is required")
        if client is None:
            try:
                import boto3
            except ImportError as exc:
                raise SignerError(
                    "awskms: keys need boto3: pip install 'privatevault-agent-dna[kms-aws]'"
                ) from exc
            client = boto3.client("kms")
        self._client = client
        self._key_id = key_id
        try:
            info = client.get_public_key(KeyId=key_id)
        except Exception as exc:
            raise SignerError(
                f"AWS KMS get_public_key failed: {type(exc).__name__}"
            ) from exc
        if info.get("KeySpec") != "ECC_NIST_EDWARDS25519":
            raise SignerError(
                f"AWS KMS key spec is {info.get('KeySpec')}, not ECC_NIST_EDWARDS25519"
            )
        if info.get("KeyUsage") != "SIGN_VERIFY":
            raise SignerError("AWS KMS key usage must be SIGN_VERIFY")
        if "ED25519_SHA_512" not in (info.get("SigningAlgorithms") or []):
            raise SignerError("AWS KMS key does not offer ED25519_SHA_512")
        self._public = ed25519_public_key_from_spki(bytes(info["PublicKey"]))

    @property
    def public_key(self) -> bytes:
        return self._public

    @property
    def description(self) -> str:
        return f"AWS KMS {self._key_id}"

    def sign(self, message: bytes) -> bytes:
        message = bytes(message)
        if len(message) > AWS_MAX_RAW_MESSAGE:
            raise SignerError(
                f"document is {len(message)} bytes; AWS KMS signs at most "
                f"{AWS_MAX_RAW_MESSAGE} bytes as pure Ed25519 (refusing to pre-hash)"
            )
        try:
            response = self._client.sign(
                KeyId=self._key_id,
                Message=message,
                MessageType="RAW",
                SigningAlgorithm="ED25519_SHA_512",
            )
        except Exception as exc:
            raise SignerError(f"AWS KMS sign failed: {type(exc).__name__}") from exc
        return _verified(self._public, message, bytes(response["Signature"]), "AWS KMS")


def _crc32c_table() -> tuple[int, ...]:
    table = []
    for n in range(256):
        crc = n
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
        table.append(crc)
    return tuple(table)


_CRC32C = _crc32c_table()


def crc32c(data: bytes) -> int:
    """CRC-32C (Castagnoli), as Cloud KMS uses for request integrity."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc = _CRC32C[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


class GcpKmsSigner:
    """Ed25519 in Google Cloud KMS (``EC_SIGN_ED25519`` key version)."""

    def __init__(self, version_name: str, client: Any = None) -> None:
        if "/cryptoKeyVersions/" not in version_name:
            raise SignerError(
                "gcpkms: needs a key version name "
                "(projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/N)"
            )
        if client is None:
            try:
                from google.cloud import kms  # type: ignore[import-not-found]
            except ImportError as exc:
                raise SignerError(
                    "gcpkms: keys need google-cloud-kms: "
                    "pip install 'privatevault-agent-dna[kms-gcp]'"
                ) from exc
            client = kms.KeyManagementServiceClient()
        self._client = client
        self._name = version_name
        try:
            info = client.get_public_key(request={"name": version_name})
        except Exception as exc:
            raise SignerError(
                f"Cloud KMS get_public_key failed: {type(exc).__name__}"
            ) from exc
        algorithm = getattr(info.algorithm, "name", str(info.algorithm))
        if algorithm != "EC_SIGN_ED25519":
            raise SignerError(
                f"Cloud KMS key algorithm is {algorithm}, not EC_SIGN_ED25519"
            )
        pem = str(info.pem)
        if getattr(info, "pem_crc32c", None) is not None and int(
            info.pem_crc32c
        ) != crc32c(pem.encode()):
            raise SignerError("Cloud KMS public key failed its CRC32C check")
        self._public = ed25519_public_key_from_spki(_pem_to_der(pem))

    @property
    def public_key(self) -> bytes:
        return self._public

    @property
    def description(self) -> str:
        return f"Cloud KMS {self._name}"

    def sign(self, message: bytes) -> bytes:
        message = bytes(message)
        try:
            response = self._client.asymmetric_sign(
                request={
                    "name": self._name,
                    "data": message,
                    "data_crc32c": crc32c(message),
                }
            )
        except Exception as exc:
            raise SignerError(f"Cloud KMS sign failed: {type(exc).__name__}") from exc
        if not response.verified_data_crc32c or response.name != self._name:
            raise SignerError("Cloud KMS did not confirm the data it signed")
        signature = bytes(response.signature)
        if int(response.signature_crc32c) != crc32c(signature):
            raise SignerError("Cloud KMS signature failed its CRC32C check")
        return _verified(self._public, message, signature, "Cloud KMS")


def is_kms_ref(value: str | None) -> bool:
    return bool(value) and str(value).startswith((AWS_PREFIX, GCP_PREFIX))


def kms_signer(ref: str, *, clients: dict[str, Any] | None = None) -> Ed25519Signer:
    """Build a KMS signer from an ``awskms:`` / ``gcpkms:`` reference."""
    clients = clients or {}
    if ref.startswith(AWS_PREFIX):
        return AwsKmsSigner(ref[len(AWS_PREFIX) :], client=clients.get("aws"))
    if ref.startswith(GCP_PREFIX):
        return GcpKmsSigner(ref[len(GCP_PREFIX) :], client=clients.get("gcp"))
    raise SignerError(f"not a KMS key reference: {ref[:16]}...")


def signer_from_seed_file(ref: str, **kw: Any) -> Ed25519Signer:
    """A key setting holding a 32-byte seed file path, or a KMS reference."""
    if is_kms_ref(ref):
        return kms_signer(ref, **kw)
    try:
        return LocalSigner(SigningKey(Path(ref).read_bytes()), f"local file {ref}")
    except (OSError, ValueError, TypeError) as exc:
        raise SignerError(f"cannot read a 32-byte Ed25519 seed from {ref}") from exc


def signer_from_hex_seed(ref: str, **kw: Any) -> Ed25519Signer:
    """A key setting holding a 64-hex seed, or a KMS reference."""
    if is_kms_ref(ref):
        return kms_signer(ref, **kw)
    try:
        return LocalSigner(
            SigningKey(ref.encode("ascii"), encoder=HexEncoder), "local seed"
        )
    except (ValueError, TypeError) as exc:
        raise SignerError(
            "signing key must be a 64-hex Ed25519 seed or a KMS reference"
        ) from exc


def as_signer(key: SigningKey | Ed25519Signer) -> Ed25519Signer:
    return LocalSigner(key) if isinstance(key, SigningKey) else key
