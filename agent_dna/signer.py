"""Runtime signer selector.

Two interchangeable Ed25519 backends behind one import surface:

    agent_dna.signer_python   PyNaCl, always available
    agent_dna.signer_bridge   Rust (pv_runtime), GIL released on the
                              hot path; requires the built wheel

Select with ``PV_USE_RUST_SIGNER=1``. Ed25519 (RFC 8032) is
deterministic, so envelopes produced by either backend verify under
the other -- proven by tests/test_rust_signer_parity.py.

Requesting the Rust backend when the wheel is absent raises at import
time rather than falling back. Silently signing with a different
implementation than the operator selected is exactly the kind of
undisclosed substitution this system exists to prevent.

``SIGNER_BACKEND`` reports which implementation is actually live, so
composition manifests and operators can assert it rather than infer
it from the environment.
"""

from __future__ import annotations

import os

from .signer_python import (
    TRUSTED_KEYS_ENV,
    parse_trusted_keys,
    verify_trusted_envelope,
)

USE_RUST = os.getenv("PV_USE_RUST_SIGNER", "0").lower() in ("1", "true", "yes")

if USE_RUST:
    try:
        from .signer_bridge import (
            KEY_ENV,
            ReceiptSigner,
            SignatureEnvelope,
            generate_keypair,
            rotate_key,
            verify_envelope,
        )
    except ImportError as exc:  # wheel absent or unloadable
        raise ImportError(
            "PV_USE_RUST_SIGNER is set but the Rust signer is "
            f"unavailable ({exc}). Build and install the wheel "
            "(maturin build --release -m rust/Cargo.toml, then pip "
            "install the artifact), or unset PV_USE_RUST_SIGNER to "
            "use the PyNaCl backend. Refusing to fall back silently: "
            "the operator selected a specific signing implementation."
        ) from exc
    SIGNER_BACKEND = "rust"
else:
    from .signer_python import (  # type: ignore[assignment]
        KEY_ENV,
        ReceiptSigner,
        SignatureEnvelope,
        generate_keypair,
        rotate_key,
        verify_envelope,
    )

    SIGNER_BACKEND = "python"

__all__ = [
    "KEY_ENV",
    "TRUSTED_KEYS_ENV",
    "SIGNER_BACKEND",
    "USE_RUST",
    "ReceiptSigner",
    "SignatureEnvelope",
    "generate_keypair",
    "parse_trusted_keys",
    "rotate_key",
    "verify_envelope",
    "verify_trusted_envelope",
]
