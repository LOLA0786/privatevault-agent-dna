"""
Rust-backed signer bridge.

Same public API as signer_python (SignatureEnvelope, ReceiptSigner,
generate_keypair, verify_signature) with signing delegated to the
Rust runtime (pv_runtime.RustReceiptSigner).

Correctness notes
-----------------
* Ed25519 (RFC 8032) is deterministic: for the same seed and hash the
  Rust and PyNaCl signatures are byte-identical, so envelopes produced
  by either implementation verify under the other. Proven by
  tests/test_rust_signer_parity.py.
* The raw seed is NOT retained on this object. It is handed to the
  Rust constructor (which holds it in zeroized memory) and the local
  reference is dropped.
* Everything except signing is re-exported from signer_python
  verbatim -- one source of truth for envelope shape and verification
  semantics.
"""

from __future__ import annotations

import os
import uuid
from typing import Optional

import pv_runtime

from .signer_python import (  # noqa: F401  (re-exports are the API)
    KEY_ENV,
    SignatureEnvelope,
    generate_keypair,
    rotate_key,
    verify_envelope,
)


class ReceiptSigner:
    """Drop-in replacement for signer_python.ReceiptSigner with the
    hot-path Ed25519 signing performed in Rust (GIL released)."""

    def __init__(
        self,
        seed_hex: Optional[str] = None,
        key_id: Optional[str] = None,
    ):
        seed = seed_hex or os.getenv(KEY_ENV)
        if not seed:
            raise RuntimeError(
                f"no signing key: pass seed_hex or set {KEY_ENV}"
            )
        self._rust = pv_runtime.RustReceiptSigner(seed)
        del seed  # no seed retained on the Python side
        self.public_key = self._rust.public_key
        self.key_id = key_id

    def sign_record(self, record) -> SignatureEnvelope:
        """Rule 4: verify the record first; a signature over an
        unverifiable record is meaningless."""
        if not record.verify():
            raise ValueError(
                "record is unsealed or tampered; refusing to sign"
            )
        return self.sign_hash(record.record_hash)

    def sign_hash(self, hash_hex: str) -> SignatureEnvelope:
        return SignatureEnvelope(
            envelope_id=f"sig-{uuid.uuid4()}",
            algorithm="Ed25519",
            signed_hash=hash_hex,
            signature=self._rust.sign_hash(hash_hex),
            public_key=self.public_key,
            key_id=self.key_id,
        )
