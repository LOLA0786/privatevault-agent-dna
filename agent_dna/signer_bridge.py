"""
Rust-backed signer bridge.

This module exposes the exact same signing primitives as signer.py,
but delegates cryptographic operations to the Rust runtime.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, Optional

import pv_runtime

from .signer_python import (
    SignatureEnvelope,
    ReceiptSigner as PythonReceiptSigner,
)


class ReceiptSigner:
    """
    Drop-in replacement for the Python ReceiptSigner.

    Keeps the same public API while using Rust for the hot-path
    cryptographic operations.
    """

    def __init__(
        self,
        seed_hex: Optional[str] = None,
        key_id: Optional[str] = None,
    ):
        self._python = PythonReceiptSigner(
            seed_hex=seed_hex,
            key_id=key_id,
        )

        self.public_key = self._python.public_key
        self.key_id = key_id

        self._seed = seed_hex

    def sign_record(self, record):
        if not record.verify():
            raise ValueError(
                "record is unsealed or tampered; refusing to sign"
            )

        return self.sign_hash(record.record_hash)

    def sign_hash(self, hash_hex: str):

        signature = pv_runtime.sign_hash(
            self._seed,
            hash_hex,
        )

        return SignatureEnvelope(
            envelope_id=f"sig-{uuid.uuid4()}",
            algorithm="Ed25519",
            signed_hash=hash_hex,
            signature=signature,
            public_key=self.public_key,
            key_id=self.key_id,
        )


generate_keypair = pv_runtime.generate_keypair
verify_signature = pv_runtime.verify_signature
