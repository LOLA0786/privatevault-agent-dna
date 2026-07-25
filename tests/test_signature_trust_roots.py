"""Explicit trust-root verification for Ed25519 receipt envelopes."""

import pytest

from agent_dna.signer import (
    ReceiptSigner,
    generate_keypair,
    parse_trusted_keys,
    verify_trusted_envelope,
)


def _signed_hash():
    keys = generate_keypair()
    signer = ReceiptSigner(keys["signing_key"])
    record_hash = "a" * 64
    envelope = signer.sign_hash(record_hash).to_dict()
    return keys, record_hash, envelope


def test_trusted_signing_key_verifies():
    keys, record_hash, envelope = _signed_hash()

    assert verify_trusted_envelope(
        envelope,
        record_hash,
        trusted_keys={keys["public_key"]},
    )


def test_mathematically_valid_unknown_key_is_rejected():
    _, record_hash, _ = _signed_hash()

    attacker = generate_keypair()
    attacker_signer = ReceiptSigner(attacker["signing_key"])
    attacker_envelope = attacker_signer.sign_hash(record_hash).to_dict()

    trusted = generate_keypair()

    assert not verify_trusted_envelope(
        attacker_envelope,
        record_hash,
        trusted_keys={trusted["public_key"]},
    )


def test_missing_trust_root_is_rejected():
    _, record_hash, envelope = _signed_hash()

    assert not verify_trusted_envelope(
        envelope,
        record_hash,
        trusted_keys=None,
    )


def test_trusted_key_environment_value_is_normalized():
    first = generate_keypair()["public_key"]
    second = generate_keypair()["public_key"]

    parsed = parse_trusted_keys(f" {first.upper()}, {second} ")

    assert parsed == {first, second}


@pytest.mark.parametrize(
    "value",
    [
        "not-hex",
        "a" * 63,
        "z" * 64,
    ],
)
def test_invalid_trusted_key_configuration_is_rejected(value):
    with pytest.raises(ValueError):
        parse_trusted_keys(value)
