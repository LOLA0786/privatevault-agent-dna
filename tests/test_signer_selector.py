"""agent_dna.signer selector: both backends expose one declared API,
the live backend is observable, and requesting an unavailable backend
fails loudly instead of substituting a different implementation."""

import importlib
import subprocess
import sys

import agent_dna.signer as signer

PUBLIC_API = {
    "KEY_ENV", "SIGNER_BACKEND", "USE_RUST", "ReceiptSigner",
    "SignatureEnvelope", "generate_keypair", "rotate_key",
    "verify_envelope",
}


def test_public_api_is_declared_and_complete():
    assert set(signer.__all__) == PUBLIC_API
    for name in PUBLIC_API:
        assert hasattr(signer, name), f"{name} missing from selector"


def test_backend_is_observable():
    assert signer.SIGNER_BACKEND in ("python", "rust")
    assert (signer.SIGNER_BACKEND == "rust") == signer.USE_RUST


def test_python_backend_signs_and_verifies_roundtrip(monkeypatch):
    monkeypatch.delenv("PV_USE_RUST_SIGNER", raising=False)
    mod = importlib.reload(signer)
    assert mod.SIGNER_BACKEND == "python"
    keys = mod.generate_keypair()
    s = mod.ReceiptSigner(keys["signing_key"])
    record_hash = "a" * 64
    env = s.sign_hash(record_hash).to_dict()
    assert mod.verify_envelope(env, record_hash) is True
    # a signature is only valid for the hash it covers
    assert mod.verify_envelope(env, "b" * 64) is False


def test_requesting_rust_without_wheel_fails_loudly():
    """Either the wheel is installed (import succeeds, backend reports
    'rust') or it is not (ImportError names the env var and the fix).
    What must never happen: importing cleanly while silently signing
    with the other implementation."""
    code = (
        "import agent_dna.signer as s; "
        "print('BACKEND=' + s.SIGNER_BACKEND)"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        env={**__import__("os").environ, "PV_USE_RUST_SIGNER": "1"},
        capture_output=True, text=True,
    )
    if proc.returncode == 0:
        assert "BACKEND=rust" in proc.stdout, (
            "PV_USE_RUST_SIGNER=1 imported cleanly but the live backend "
            "is not rust -- silent substitution")
    else:
        assert "PV_USE_RUST_SIGNER" in proc.stderr
        assert "maturin" in proc.stderr or "wheel" in proc.stderr


def test_selector_does_not_leak_module_internals():
    """`import *` previously re-exported every non-underscore name of
    whichever backend loaded. The API is now declared, so the surface
    is stable across backends."""
    leaked = {n for n in dir(signer)
              if not n.startswith("_")
              and n not in PUBLIC_API
              and n not in {"annotations", "os"}}
    assert not leaked, f"undeclared names on the selector: {leaked}"
