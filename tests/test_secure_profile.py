"""Secure-defaults profile: fail closed when critical operator material is absent."""

from __future__ import annotations

import json

import pytest

from agent_dna.apikeys import generate_key
from agent_dna.composition import RuntimeConfig, build_production_runtime
from agent_dna.signer_python import ReceiptSigner


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
