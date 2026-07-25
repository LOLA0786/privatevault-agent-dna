"""Runtime signing must be anchored to explicit trusted public keys."""

import pytest

from agent_dna.composition import RuntimeConfig, build_production_runtime
from agent_dna.signer import generate_keypair


def test_runtime_refuses_self_attested_signer(tmp_path, monkeypatch):
    keys = generate_keypair()
    monkeypatch.setenv("PV_RECEIPT_SIGNING_KEY", keys["signing_key"])

    with pytest.raises(RuntimeError, match="PV_TRUSTED_PUBLIC_KEYS"):
        build_production_runtime(RuntimeConfig(db_path=str(tmp_path / "untrusted.db")))


def test_runtime_accepts_explicitly_pinned_signer(tmp_path, monkeypatch):
    keys = generate_keypair()
    monkeypatch.setenv("PV_RECEIPT_SIGNING_KEY", keys["signing_key"])

    runtime = build_production_runtime(
        RuntimeConfig(
            db_path=str(tmp_path / "trusted.db"),
            trusted_public_keys=frozenset({keys["public_key"]}),
        )
    )

    assert runtime.signer is not None
    assert runtime.signer.public_key == keys["public_key"]
    assert runtime.trusted_public_keys == {keys["public_key"]}
    assert "1 configured trust root" in runtime.composition["signing"]["detail"]

    runtime.store.close()
    runtime.breaker.close()


def test_runtime_config_parses_trusted_keys_from_environment(monkeypatch):
    first = generate_keypair()["public_key"]
    second = generate_keypair()["public_key"]

    monkeypatch.setenv(
        "PV_TRUSTED_PUBLIC_KEYS",
        f"{first},{second}",
    )

    config = RuntimeConfig.from_env()

    assert config.trusted_public_keys == {first, second}
