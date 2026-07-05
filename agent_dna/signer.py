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
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

KEY_ENV = "PV_RECEIPT_SIGNING_KEY"


@dataclass
class SignatureEnvelope:
    envelope_id: str
    algorithm: str
    signed_hash: str          # record_hash of the signed record
    signature: str            # hex
    public_key: str           # hex
    key_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "envelope_id": self.envelope_id,
            "algorithm": self.algorithm,
            "signed_hash": self.signed_hash,
            "signature": self.signature,
            "public_key": self.public_key,
            "key_id": self.key_id,
        }


def generate_keypair() -> Dict[str, str]:
    sk = SigningKey.generate()
    return {
        "signing_key": sk.encode(encoder=HexEncoder).decode(),
        "public_key": sk.verify_key.encode(encoder=HexEncoder).decode(),
    }


class ReceiptSigner:
    def __init__(self, seed_hex: Optional[str] = None, key_id: Optional[str] = None):
        seed = seed_hex or os.getenv(KEY_ENV)
        if not seed:
            raise RuntimeError(
                f"no signing key: pass seed_hex or set {KEY_ENV}"
            )
        self._sk = SigningKey(seed, encoder=HexEncoder)
        self.public_key = self._sk.verify_key.encode(encoder=HexEncoder).decode()
        self.key_id = key_id

    def sign_record(self, record) -> SignatureEnvelope:
        """Sign a sealed record. Refuses unsealed/tampered input
        (Rule 4: a signature over an unverifiable record is meaningless)."""
        if not record.verify():
            raise ValueError("record is unsealed or tampered; refusing to sign")
        sig = self._sk.sign(record.record_hash.encode()).signature.hex()
        return SignatureEnvelope(
            envelope_id=f"sig-{uuid.uuid4()}",
            algorithm="Ed25519",
            signed_hash=record.record_hash,
            signature=sig,
            public_key=self.public_key,
            key_id=self.key_id,
        )


def verify_envelope(envelope: Dict[str, Any], record_hash: str) -> bool:
    """Standalone verification: envelope + the record_hash it claims to
    sign. No dependency on the signer instance or the record class."""
    if envelope.get("algorithm") != "Ed25519":
        return False
    if envelope.get("signed_hash") != record_hash:
        return False
    try:
        VerifyKey(
            envelope["public_key"], encoder=HexEncoder
        ).verify(
            record_hash.encode(),
            bytes.fromhex(envelope["signature"]),
        )
        return True
    except (BadSignatureError, KeyError, ValueError):
        return False
