"""Rust <-> Python Ed25519 signer parity.

Ed25519 is deterministic, so the two implementations must produce
byte-identical signatures for the same seed + hash, and each must
verify the other's output. Also exercises the PV_USE_RUST_SIGNER=1
import path that was previously broken and untested.

Skips cleanly when pv_runtime is not installed.
"""

from __future__ import annotations

import hashlib
import importlib

import pytest

pv_runtime = pytest.importorskip(
    "pv_runtime", reason="Rust wheel not installed"
)

from agent_dna import (  # noqa: E402
    signer_bridge,
    signer_python,
)

SEED = hashlib.sha256(b"pv-signer-parity-fixed-seed").hexdigest()
HASH = hashlib.sha256(b"some sealed record hash preimage").hexdigest()


def test_public_keys_identical_for_same_seed():
    py = signer_python.ReceiptSigner(seed_hex=SEED)
    rs = signer_bridge.ReceiptSigner(seed_hex=SEED)
    assert py.public_key == rs.public_key


def test_signatures_byte_identical():
    py = signer_python.ReceiptSigner(seed_hex=SEED)
    rs = signer_bridge.ReceiptSigner(seed_hex=SEED)
    assert (
        py.sign_hash(HASH).signature == rs.sign_hash(HASH).signature
    ), "Ed25519 is deterministic -- differing signatures mean a broken impl"


def test_cross_verification_both_directions():
    py = signer_python.ReceiptSigner(seed_hex=SEED)
    rs = signer_bridge.ReceiptSigner(seed_hex=SEED)
    py_env = py.sign_hash(HASH)
    rs_env = rs.sign_hash(HASH)

    # Rust verifier accepts both
    assert pv_runtime.verify_signature(py.public_key, HASH, py_env.signature)
    assert pv_runtime.verify_signature(rs.public_key, HASH, rs_env.signature)
    # and rejects a flipped signature
    bad = ("0" if rs_env.signature[0] != "0" else "1") + rs_env.signature[1:]
    assert not pv_runtime.verify_signature(rs.public_key, HASH, bad)


def test_bridge_refuses_unsealed_record():
    from agent_dna.decision_record import DRP_V01, DecisionRecord

    rec = DecisionRecord(
        protocol_version=DRP_V01,
        decision_id="d-sign-1",
        parent_decision=None,
        agent_id="a",
        capability="x",
        decision="allow",
        triggered_by="baseline",
        reason="",
        severity="none",
        drift_score=0.0,
        evidence=[],
        evidence_strength=0.0,
        arguments_digest="",
        outcome="pending",
    )
    rs = signer_bridge.ReceiptSigner(seed_hex=SEED)
    with pytest.raises(ValueError, match="unsealed or tampered"):
        rs.sign_record(rec)  # never sealed
    rec.seal()
    env = rs.sign_record(rec)
    assert env.signed_hash == rec.record_hash


def test_env_flag_selects_rust_backend(monkeypatch):
    """PV_USE_RUST_SIGNER=1 must import cleanly and expose the same
    API surface -- this exact path raised AttributeError before."""
    monkeypatch.setenv("PV_USE_RUST_SIGNER", "1")
    import agent_dna.signer as signer_mod

    mod = importlib.reload(signer_mod)
    s = mod.ReceiptSigner(seed_hex=SEED)
    env = s.sign_hash(HASH)
    assert env.algorithm == "Ed25519"
    assert pv_runtime.verify_signature(s.public_key, HASH, env.signature)

    # restore the default backend for the rest of the suite
    monkeypatch.setenv("PV_USE_RUST_SIGNER", "0")
    importlib.reload(signer_mod)
