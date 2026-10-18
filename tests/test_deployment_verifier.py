"""tools/verify_deployment.py: config claims AND observed blocking.

A deployment passes only when it reports lineage=enforce, signed decisions
and durable grant state, and actually refuses an unbound approval and a
self-approval when probed.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent_dna.apikeys import generate_key
from agent_dna.lineage import lineage_mode
from agent_dna.signer_python import generate_keypair

REPO = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "verify_deployment", REPO / "tools" / "verify_deployment.py"
)
verifier = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verifier)

AGENT = "probe-agent"


@pytest.fixture()
def deploy(tmp_path, monkeypatch):
    key = generate_key(AGENT, "full")
    (tmp_path / "keys.json").write_text(
        json.dumps({key["hash"]: {"name": AGENT, "scope": "full"}})
    )
    (tmp_path / "grants.json").write_text(
        json.dumps([{"agent_id": AGENT, "capability": "payments.read_balance"}])
    )
    signing = generate_keypair()
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "pv.db"))
    monkeypatch.setenv("PV_API_KEYS_FILE", str(tmp_path / "keys.json"))
    monkeypatch.setenv("PV_GRANTS_FILE", str(tmp_path / "grants.json"))
    monkeypatch.setenv("PV_RECEIPT_SIGNING_KEY", signing["signing_key"])
    monkeypatch.setenv("PV_TRUSTED_PUBLIC_KEYS", signing["public_key"])
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    monkeypatch.delenv("PV_SECURE_PROFILE", raising=False)

    def run(mode: str, probe: bool = True):
        monkeypatch.setenv("PV_LINEAGE", mode)
        import api.server as server

        importlib.reload(server)
        with TestClient(server.app) as client:

            def call(method, path, body):
                r = client.request(
                    method, path, json=body, headers={"X-API-Key": key["key"]}
                )
                return r.status_code, r.json()

            return dict(
                (name, ok) for name, ok, _ in verifier.run_checks(call, AGENT, probe)
            )

    return run


def test_enforced_deployment_passes_config_and_probes(deploy):
    checks = deploy("enforce")
    assert checks == {
        "lineage enforced": True,
        "decisions signed": True,
        "grants from file": True,
        "durable grant spend": True,
        "durable grant revocation": True,
        "probe: unbound approval refused": True,
        "probe: self-approval refused": True,
    }


def test_shadow_mode_fails_config_and_behaviour(deploy):
    checks = deploy("shadow")
    assert checks["lineage enforced"] is False
    assert checks["probe: unbound approval refused"] is False
    assert checks["probe: self-approval refused"] is False


def test_lineage_off_fails(deploy):
    checks = deploy("off")
    assert checks["lineage enforced"] is False
    assert checks["probe: self-approval refused"] is False


def test_config_only_mode_skips_probes(deploy):
    checks = deploy("enforce", probe=False)
    assert all(checks.values()) and not any(k.startswith("probe") for k in checks)


def test_secure_profile_defaults_to_enforce(monkeypatch):
    monkeypatch.setenv("PV_SECURE_PROFILE", "1")
    monkeypatch.delenv("PV_LINEAGE", raising=False)
    assert lineage_mode() == "enforce"


@pytest.mark.parametrize("weaker", ["off", "shadow"])
def test_secure_profile_refuses_weaker_lineage(monkeypatch, weaker):
    monkeypatch.setenv("PV_SECURE_PROFILE", "1")
    monkeypatch.setenv("PV_LINEAGE", weaker)
    with pytest.raises(RuntimeError, match="requires PV_LINEAGE=enforce"):
        lineage_mode()


def test_default_without_secure_profile_is_unchanged(monkeypatch):
    monkeypatch.delenv("PV_SECURE_PROFILE", raising=False)
    monkeypatch.delenv("PV_LINEAGE", raising=False)
    assert lineage_mode() == "off"


@pytest.mark.skipif(
    not __import__("os").environ.get("TEST_DATABASE_URL"),
    reason="set TEST_DATABASE_URL to run the PostgreSQL tests",
)
def test_a_postgresql_deployment_passes(deploy, monkeypatch, request):
    """Found by installing the Helm chart: the verifier only accepted the
    SQLite wording, so every PostgreSQL deployment failed its own check."""
    monkeypatch.setenv("PV_DATABASE_URL", request.getfixturevalue("dsn"))
    checks = deploy("enforce")
    assert all(checks.values()), checks
