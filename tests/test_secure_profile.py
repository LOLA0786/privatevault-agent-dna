"""Secure-defaults profile: fail closed when critical operator material is absent."""

from __future__ import annotations

import json

import pytest
from nacl.signing import SigningKey

from agent_dna.apikeys import generate_key
from agent_dna.authority_v01 import (
    CANONICALIZATION,
    TRUST_SPEC,
    encode_public_key,
)
from agent_dna.composition import RuntimeConfig, build_production_runtime
from agent_dna.connector.adapters.execution_trust import (
    validate_execution_trust_bundle,
    DISPATCH_WITNESS_KEY_ENV,
    EXECUTION_TRUST_BUNDLE_ENV,
)
from agent_dna.signer_python import ReceiptSigner


def _write_execution_trust(tmp_path, monkeypatch) -> None:
    runtime_key = SigningKey.generate()
    witness_key = SigningKey.generate()
    bundle = {
        "spec": TRUST_SPEC,
        "canonicalization": CANONICALIZATION,
        "organisation_id": "secure.example",
        "bundle_version": 1,
        "pinned_at": "2026-08-10T11:00:00Z",
        "keys": [
            {
                "key_id": "ea-signer",
                "principal": "execution-runtime@secure.example",
                "algorithm": "ed25519",
                "public_key": encode_public_key(runtime_key),
                "usages": ["execution_authorization_signer"],
            },
            {
                "key_id": "witness-01",
                "principal": "egress-witness@secure.example",
                "algorithm": "ed25519",
                "public_key": encode_public_key(witness_key),
                "usages": ["dispatch_witness_signer", "closure_signer"],
            },
        ],
    }
    bundle_path = tmp_path / "execution-trust.json"
    bundle_path.write_text(json.dumps(bundle))
    key_path = tmp_path / "dispatch-witness.key"
    key_path.write_bytes(bytes(witness_key))
    monkeypatch.setenv(EXECUTION_TRUST_BUNDLE_ENV, str(bundle_path))
    monkeypatch.setenv(DISPATCH_WITNESS_KEY_ENV, str(key_path))


def test_secure_profile_requires_keys_and_grants(tmp_path, monkeypatch):
    monkeypatch.setenv("PV_SECURE_PROFILE", "1")
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    monkeypatch.delenv("PV_API_KEYS_FILE", raising=False)
    monkeypatch.delenv("PV_GRANTS_FILE", raising=False)
    with pytest.raises(RuntimeError, match="PV_API_KEYS_FILE"):
        build_production_runtime(RuntimeConfig(db_path=str(tmp_path / "a.db")))


def test_secure_profile_refuses_allow_no_auth(tmp_path, monkeypatch):
    monkeypatch.setenv("PV_SECURE_PROFILE", "1")
    monkeypatch.setenv("PV_ALLOW_NO_AUTH", "1")
    keys = tmp_path / "keys.json"
    op = generate_key("a", "full")
    keys.write_text(json.dumps({op["hash"]: {"name": "a", "scope": "full"}}))
    grants = tmp_path / "grants.json"
    grants.write_text("[]")
    with pytest.raises(RuntimeError, match="PV_ALLOW_NO_AUTH"):
        build_production_runtime(
            RuntimeConfig(
                db_path=str(tmp_path / "b.db"),
                keys_file=str(keys),
                grants_file=str(grants),
            )
        )


def test_secure_profile_forces_loop_and_cross_agent_require(tmp_path, monkeypatch):
    monkeypatch.setenv("PV_SECURE_PROFILE", "1")
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    monkeypatch.setenv("PV_CROSS_AGENT_REQUIRE_EXECUTION_ID", "0")
    monkeypatch.setenv("PV_LOOP_EVENTS_REQUIRED", "0")
    seed = "11" * 32
    monkeypatch.setenv("PV_RECEIPT_SIGNING_KEY", seed)
    pubkey = ReceiptSigner(seed_hex=seed).public_key
    op = generate_key("sec-agent", "full")
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps({op["hash"]: {"name": "sec-agent", "scope": "full"}}))
    grants = tmp_path / "grants.json"
    grants.write_text(
        json.dumps(
            [
                {
                    "agent_id": "sec-agent",
                    "capability": "crm.read_contact",
                    "granted_by": "test",
                }
            ]
        )
    )
    _write_execution_trust(tmp_path, monkeypatch)
    rt = build_production_runtime(
        RuntimeConfig(
            db_path=str(tmp_path / "c.db"),
            keys_file=str(keys),
            grants_file=str(grants),
            trusted_public_keys=frozenset({pubkey}),
        )
    )
    assert rt.composition["secure_profile"]["status"] == "attached"
    assert rt.loop_events_required is True
    assert rt.composition["cross_agent"]["require_execution_id"] == "true"
    assert rt.composition["authorization"]["mode"] == "grants_file"
    assert rt.execution_trust_bundle is not None
    assert rt.egress_sidecar is not None
    assert rt.composition["egress_sidecar"]["status"] == "attached"


def test_secure_profile_requires_execution_trust_bundle(tmp_path, monkeypatch):
    monkeypatch.setenv("PV_SECURE_PROFILE", "1")
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    monkeypatch.delenv(EXECUTION_TRUST_BUNDLE_ENV, raising=False)
    seed = "11" * 32
    monkeypatch.setenv("PV_RECEIPT_SIGNING_KEY", seed)
    pubkey = ReceiptSigner(seed_hex=seed).public_key
    keys = tmp_path / "keys.json"
    op = generate_key("a", "full")
    keys.write_text(json.dumps({op["hash"]: {"name": "a", "scope": "full"}}))
    grants = tmp_path / "grants.json"
    grants.write_text("[]")
    with pytest.raises(RuntimeError, match="PV_EXECUTION_TRUST_BUNDLE_FILE"):
        build_production_runtime(
            RuntimeConfig(
                db_path=str(tmp_path / "bundle.db"),
                keys_file=str(keys),
                grants_file=str(grants),
                trusted_public_keys=frozenset({pubkey}),
            )
        )


def test_secure_profile_requires_dispatch_witness_key(tmp_path, monkeypatch):
    monkeypatch.setenv("PV_SECURE_PROFILE", "1")
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    monkeypatch.delenv(DISPATCH_WITNESS_KEY_ENV, raising=False)
    seed = "11" * 32
    monkeypatch.setenv("PV_RECEIPT_SIGNING_KEY", seed)
    pubkey = ReceiptSigner(seed_hex=seed).public_key
    keys = tmp_path / "keys.json"
    op = generate_key("a", "full")
    keys.write_text(json.dumps({op["hash"]: {"name": "a", "scope": "full"}}))
    grants = tmp_path / "grants.json"
    grants.write_text("[]")
    _write_execution_trust(tmp_path, monkeypatch)
    monkeypatch.delenv(DISPATCH_WITNESS_KEY_ENV, raising=False)
    with pytest.raises(RuntimeError, match="PV_DISPATCH_WITNESS_KEY"):
        build_production_runtime(
            RuntimeConfig(
                db_path=str(tmp_path / "witness.db"),
                keys_file=str(keys),
                grants_file=str(grants),
                trusted_public_keys=frozenset({pubkey}),
            )
        )


def test_secure_profile_rejects_bundle_missing_required_usages(tmp_path, monkeypatch):
    monkeypatch.setenv("PV_SECURE_PROFILE", "1")
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    seed = "11" * 32
    monkeypatch.setenv("PV_RECEIPT_SIGNING_KEY", seed)
    pubkey = ReceiptSigner(seed_hex=seed).public_key
    keys = tmp_path / "keys.json"
    op = generate_key("a", "full")
    keys.write_text(json.dumps({op["hash"]: {"name": "a", "scope": "full"}}))
    grants = tmp_path / "grants.json"
    grants.write_text("[]")
    _write_execution_trust(tmp_path, monkeypatch)
    broken = {
        "spec": TRUST_SPEC,
        "canonicalization": CANONICALIZATION,
        "organisation_id": "secure.example",
        "bundle_version": 1,
        "pinned_at": "2026-08-10T11:00:00Z",
        "keys": [
            {
                "key_id": "ea-signer",
                "principal": "execution-runtime@secure.example",
                "algorithm": "ed25519",
                "public_key": encode_public_key(SigningKey.generate()),
                "usages": ["execution_authorization_signer"],
            }
        ],
    }
    bundle_path = tmp_path / "execution-trust.json"
    bundle_path.write_text(json.dumps(broken))
    monkeypatch.setenv(EXECUTION_TRUST_BUNDLE_ENV, str(bundle_path))
    with pytest.raises(RuntimeError, match="missing required key usages"):
        build_production_runtime(
            RuntimeConfig(
                db_path=str(tmp_path / "usages.db"),
                keys_file=str(keys),
                grants_file=str(grants),
                trusted_public_keys=frozenset({pubkey}),
            )
        )


def test_secure_profile_requires_signing_key(tmp_path, monkeypatch):
    monkeypatch.setenv("PV_SECURE_PROFILE", "1")
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    monkeypatch.delenv("PV_RECEIPT_SIGNING_KEY", raising=False)
    keys = tmp_path / "keys.json"
    op = generate_key("a", "full")
    keys.write_text(json.dumps({op["hash"]: {"name": "a", "scope": "full"}}))
    grants = tmp_path / "grants.json"
    grants.write_text("[]")
    with pytest.raises(RuntimeError, match="PV_RECEIPT_SIGNING_KEY"):
        build_production_runtime(
            RuntimeConfig(
                db_path=str(tmp_path / "sign.db"),
                keys_file=str(keys),
                grants_file=str(grants),
            )
        )


def test_secure_profile_rejects_bundle_missing_closure_signer(tmp_path, monkeypatch):
    monkeypatch.setenv("PV_SECURE_PROFILE", "1")
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    seed = "11" * 32
    monkeypatch.setenv("PV_RECEIPT_SIGNING_KEY", seed)
    pubkey = ReceiptSigner(seed_hex=seed).public_key
    keys = tmp_path / "keys.json"
    op = generate_key("a", "full")
    keys.write_text(json.dumps({op["hash"]: {"name": "a", "scope": "full"}}))
    grants = tmp_path / "grants.json"
    grants.write_text("[]")
    _write_execution_trust(tmp_path, monkeypatch)
    runtime_key = SigningKey.generate()
    witness_key = SigningKey.generate()
    broken = {
        "spec": TRUST_SPEC,
        "canonicalization": CANONICALIZATION,
        "organisation_id": "secure.example",
        "bundle_version": 1,
        "pinned_at": "2026-08-10T11:00:00Z",
        "keys": [
            {
                "key_id": "ea-signer",
                "principal": "execution-runtime@secure.example",
                "algorithm": "ed25519",
                "public_key": encode_public_key(runtime_key),
                "usages": ["execution_authorization_signer"],
            },
            {
                "key_id": "witness-01",
                "principal": "egress-witness@secure.example",
                "algorithm": "ed25519",
                "public_key": encode_public_key(witness_key),
                "usages": ["dispatch_witness_signer"],
            },
        ],
    }
    bundle_path = tmp_path / "execution-trust.json"
    bundle_path.write_text(json.dumps(broken))
    key_path = tmp_path / "dispatch-witness.key"
    key_path.write_bytes(bytes(witness_key))
    monkeypatch.setenv(EXECUTION_TRUST_BUNDLE_ENV, str(bundle_path))
    monkeypatch.setenv(DISPATCH_WITNESS_KEY_ENV, str(key_path))
    with pytest.raises(RuntimeError, match="missing required key usages"):
        build_production_runtime(
            RuntimeConfig(
                db_path=str(tmp_path / "closure.db"),
                keys_file=str(keys),
                grants_file=str(grants),
                trusted_public_keys=frozenset({pubkey}),
            )
        )


def test_secure_profile_refuses_credentials_without_allowlists(tmp_path, monkeypatch):
    monkeypatch.setenv("PV_SECURE_PROFILE", "1")
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    monkeypatch.setenv("PV_UPSTREAM_TOKEN", "secret-token")
    monkeypatch.delenv("PV_EGRESS_ALLOWED_DESTINATIONS", raising=False)
    monkeypatch.delenv("PV_EGRESS_ALLOWED_AUDIENCES", raising=False)
    seed = "11" * 32
    monkeypatch.setenv("PV_RECEIPT_SIGNING_KEY", seed)
    pubkey = ReceiptSigner(seed_hex=seed).public_key
    keys = tmp_path / "keys.json"
    op = generate_key("a", "full")
    keys.write_text(json.dumps({op["hash"]: {"name": "a", "scope": "full"}}))
    grants = tmp_path / "grants.json"
    grants.write_text("[]")
    _write_execution_trust(tmp_path, monkeypatch)
    with pytest.raises(RuntimeError, match="PV_EGRESS_ALLOWED"):
        build_production_runtime(
            RuntimeConfig(
                db_path=str(tmp_path / "cred.db"),
                keys_file=str(keys),
                grants_file=str(grants),
                trusted_public_keys=frozenset({pubkey}),
            )
        )


def test_secure_profile_refuses_credential_audience_mismatch_allowlist(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("PV_SECURE_PROFILE", "1")
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    monkeypatch.setenv("PV_UPSTREAM_TOKEN", "secret-token")
    monkeypatch.setenv("PV_EGRESS_ALLOWED_DESTINATIONS", "payments.store.example")
    monkeypatch.setenv("PV_EGRESS_ALLOWED_AUDIENCES", "other.example")
    seed = "11" * 32
    monkeypatch.setenv("PV_RECEIPT_SIGNING_KEY", seed)
    pubkey = ReceiptSigner(seed_hex=seed).public_key
    keys = tmp_path / "keys.json"
    op = generate_key("a", "full")
    keys.write_text(json.dumps({op["hash"]: {"name": "a", "scope": "full"}}))
    grants = tmp_path / "grants.json"
    grants.write_text("[]")
    _write_execution_trust(tmp_path, monkeypatch)
    rt = build_production_runtime(
        RuntimeConfig(
            db_path=str(tmp_path / "aud.db"),
            keys_file=str(keys),
            grants_file=str(grants),
            trusted_public_keys=frozenset({pubkey}),
        )
    )
    assert rt.egress_sidecar is not None
    transport = rt.egress_sidecar.transport
    assert transport.allowed_audiences == frozenset({"other.example"})
    assert transport.credentials_headers.get("Authorization") == "Bearer secret-token"


def test_secure_profile_requires_trust_roots(tmp_path, monkeypatch):
    monkeypatch.setenv("PV_SECURE_PROFILE", "1")
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    monkeypatch.setenv("PV_RECEIPT_SIGNING_KEY", "00" * 32)
    keys = tmp_path / "keys.json"
    op = generate_key("a", "full")
    keys.write_text(json.dumps({op["hash"]: {"name": "a", "scope": "full"}}))
    grants = tmp_path / "grants.json"
    grants.write_text("[]")
    with pytest.raises(RuntimeError, match="PV_TRUSTED_PUBLIC_KEYS"):
        build_production_runtime(
            RuntimeConfig(
                db_path=str(tmp_path / "trust.db"),
                keys_file=str(keys),
                grants_file=str(grants),
                trusted_public_keys=frozenset(),
            )
        )


def test_execution_bundle_refuses_mint_key_as_its_own_witness():
    """A key cannot both mint permits and witness their dispatch."""
    dual = SigningKey.generate()
    bundle = {
        "spec": TRUST_SPEC,
        "canonicalization": CANONICALIZATION,
        "organisation_id": "secure.example",
        "bundle_version": 1,
        "pinned_at": "2026-08-10T11:00:00Z",
        "keys": [
            {
                "key_id": "dual-role",
                "principal": "runtime@secure.example",
                "algorithm": "ed25519",
                "public_key": encode_public_key(dual),
                "usages": [
                    "execution_authorization_signer",
                    "dispatch_witness_signer",
                    "closure_signer",
                ],
            }
        ],
    }
    with pytest.raises(RuntimeError, match="independent observer"):
        validate_execution_trust_bundle(bundle)
