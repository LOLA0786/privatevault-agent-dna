"""
ReceiptSigner — Ed25519 signing per drp-spec docs/SIGNING.md.

Rule 1: sign the record_hash (ASCII hex bytes), never a
        re-canonicalized body.
Rule 2: chain links are inside record_hash, so signatures cover
        history automatically.
Rule 3: detached envelope; the record references it via receipt_ref
        and a signed_as edge — this module is the producer that
        activates both.
Rule 4: verify record first, signature second.

Key handling: 64-char hex seed from PV_RECEIPT_SIGNING_KEY (same env
var as the PrivateVault.ai signer for operational continuity), or an
explicit seed for tests. generate_keypair() for provisioning.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from collections.abc import Collection
from dataclasses import dataclass
from typing import Any

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

KEY_ENV = "PV_RECEIPT_SIGNING_KEY"
TRUSTED_KEYS_ENV = "PV_TRUSTED_PUBLIC_KEYS"


@dataclass
class SignatureEnvelope:
    envelope_id: str
    algorithm: str
    signed_hash: str  # record_hash of the signed record
    signature: str  # hex
    public_key: str  # hex
    key_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope_id": self.envelope_id,
            "algorithm": self.algorithm,
            "signed_hash": self.signed_hash,
            "signature": self.signature,
            "public_key": self.public_key,
            "key_id": self.key_id,
        }


def generate_keypair() -> dict[str, str]:
    sk = SigningKey.generate()
    return {
        "signing_key": sk.encode(encoder=HexEncoder).decode(),
        "public_key": sk.verify_key.encode(encoder=HexEncoder).decode(),
    }


def parse_trusted_keys(value: str | None) -> frozenset[str]:
    keys = frozenset(
        item.strip().lower() for item in (value or "").split(",") if item.strip()
    )

    for key in keys:
        if len(key) != 64:
            raise ValueError("trusted Ed25519 public keys must be 64 hex characters")

        try:
            bytes.fromhex(key)
        except ValueError as exc:
            raise ValueError("trusted Ed25519 public keys must be hexadecimal") from exc

    return keys


class ReceiptSigner:
    def __init__(self, seed_hex: str | None = None, key_id: str | None = None):
        seed = seed_hex or os.getenv(KEY_ENV)
        if not seed:
            raise RuntimeError(f"no signing key: pass seed_hex or set {KEY_ENV}")
        self._sk = SigningKey(seed, encoder=HexEncoder)
        self.public_key = self._sk.verify_key.encode(encoder=HexEncoder).decode()
        self.key_id = key_id

    def sign_record(self, record) -> SignatureEnvelope:
        """Sign a sealed record. Refuses unsealed/tampered input
        (Rule 4: a signature over an unverifiable record is meaningless)."""
        if not record.verify():
            raise ValueError("record is unsealed or tampered; refusing to sign")
        return self.sign_hash(record.record_hash)

    def sign_hash(self, hash_hex: str) -> SignatureEnvelope:
        """Sign an arbitrary hex-encoded hash directly -- the general
        primitive sign_record uses internally. Used for signing
        artifacts that aren't DecisionRecords (e.g. export manifests)
        but still want the same envelope shape and verify_envelope
        compatibility."""
        sig = self._sk.sign(hash_hex.encode()).signature.hex()
        return SignatureEnvelope(
            envelope_id=f"sig-{uuid.uuid4()}",
            algorithm="Ed25519",
            signed_hash=hash_hex,
            signature=sig,
            public_key=self.public_key,
            key_id=self.key_id,
        )


def rotate_key(old_seed_hex: str, new_seed_hex: str | None = None) -> dict[str, str]:
    """Explicit key rotation: produces a new envelope binding old->new.
    Industrial standard requires rotation events to be audit-logged."""
    old_sk = SigningKey(old_seed_hex, encoder=HexEncoder)
    new_seed = new_seed_hex or SigningKey.generate().encode(encoder=HexEncoder).decode()
    new_sk = SigningKey(new_seed, encoder=HexEncoder)
    rotation_hash = hashlib.sha256((old_seed_hex + new_seed).encode()).hexdigest()
    envelope = SignatureEnvelope(
        envelope_id=f"rotate-{uuid.uuid4()}",
        algorithm="Ed25519-key-rotation",
        signed_hash=rotation_hash,
        signature=old_sk.sign(rotation_hash.encode()).signature.hex(),
        public_key=old_sk.verify_key.encode(encoder=HexEncoder).decode(),
        key_id=f"rotated-to-{new_sk.verify_key.encode(encoder=HexEncoder).decode()[:16]}",
    )
    return {
        "rotation_envelope": envelope.to_dict(),
        "new_public_key": new_sk.verify_key.encode(encoder=HexEncoder).decode(),
        "new_seed_hint": "store securely; not in logs",
    }


def verify_envelope(envelope: dict[str, Any], record_hash: str) -> bool:
    """Standalone verification: envelope + the record_hash it claims to
    sign. No dependency on the signer instance or the record class."""
    if envelope.get("algorithm") != "Ed25519":
        return False
    if envelope.get("signed_hash") != record_hash:
        return False
    try:
        VerifyKey(envelope["public_key"], encoder=HexEncoder).verify(
            record_hash.encode(),
            bytes.fromhex(envelope["signature"]),
        )
        return True
    except (BadSignatureError, KeyError, ValueError):
        return False


def verify_trusted_envelope(
    envelope: dict[str, Any],
    record_hash: str,
    *,
    trusted_keys: Collection[str] | None,
) -> bool:
    """Verify a signature only when its public key is explicitly trusted."""
    if not trusted_keys:
        return False

    public_key = envelope.get("public_key")
    normalized_trust = {key.lower() for key in trusted_keys}

    if not isinstance(public_key, str) or public_key.lower() not in normalized_trust:
        return False

    return verify_envelope(envelope, record_hash)
