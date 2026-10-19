"""tools/init_secure_profile.py: the secure profile starts from one command.

External retests (2026-10-15/16) could not start PV_SECURE_PROFILE=1: no
tool produced the execution signer, dispatch witness, closure signer and
trust bundle together. These tests provision a directory, start the real
API from it, and run the deployment verifier against it.
"""

from __future__ import annotations

import importlib
import json
import os
import shlex
import stat
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import init_secure_profile as isp  # noqa: E402
import verify_deployment as vd  # noqa: E402


def _load_env(path: Path, monkeypatch) -> dict[str, str]:
    for name in [n for n in os.environ if n.startswith("PV_")]:
        monkeypatch.delenv(name)
    env = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        env[key] = shlex.split(value)[0]
        monkeypatch.setenv(key, env[key])
    return env


@pytest.fixture
def provisioned(tmp_path, capsys):
    out = tmp_path / "secure"
    rc = isp.main(
        [
            "--out",
            str(out),
            "--org",
            "acme.example",
            "--grant",
            "treasury-agent=payments.pay_invoice",
        ]
    )
    assert rc == 0
    printed = capsys.readouterr().out
    return out, printed


def test_secrets_are_private_and_never_printed(provisioned):
    out, printed = provisioned
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    for name in ("secure.env", "execution-signer.key", "dispatch-witness.key"):
        assert stat.S_IMODE((out / name).stat().st_mode) == 0o600, name
    env_text = (out / "secure.env").read_text(encoding="utf-8")
    for line in env_text.splitlines():
        if line.startswith(("PV_OPERATOR_KEY=", "PV_RECEIPT_SIGNING_KEY=")):
            secret = shlex.split(line.split("=", 1)[1])[0]
            assert secret and secret not in printed
    assert "pv_" not in (out / "keys.json").read_text(encoding="utf-8")


def test_secure_profile_starts_and_deployment_verifier_passes(provisioned, monkeypatch):
    out, _ = provisioned
    # Declare one operation so an ungranted capability reaches the ladder
    # (ADR 0025: undeclared operations are blocked before it).
    registry = json.loads((out / "operations.json").read_text(encoding="utf-8"))
    assert registry["operations"] == []  # the profile starts with none
    registry["operations"].append(
        {
            "operation_id": "fs-delete-probe",
            "capability": "fs.delete",
            "transport": "https",
            "destination": "example.test",
            "operation": "GET /v1/resource",
            "parameters_schema": {"type": "object"},
        }
    )
    (out / "operations.json").write_text(json.dumps(registry), encoding="utf-8")
    env = _load_env(out / "secure.env", monkeypatch)
    import api.server as server

    importlib.reload(server)
    headers = {"X-API-Key": env["PV_OPERATOR_KEY"]}
    with TestClient(server.app) as client:
        assert client.get("/ready").status_code == 200

        def call(method, path, body):
            response = client.request(method, path, json=body, headers=headers)
            return response.status_code, response.json()

        results = vd.run_checks(call, "operator", probe=True)
        assert results and all(ok for _, ok, _ in results), results
        runtime = client.get("/v1/runtime", headers=headers).json()["composition"]
        assert runtime["secure_profile"]["status"] == "attached"
        assert runtime["egress_sidecar"]["status"] == "attached"

        # no grant at all: a hard block under the secure profile (S12)
        from tests.decide_binding import decide_json

        ungranted = client.post(
            "/v1/decide", json=decide_json("operator", "fs.delete"), headers=headers
        )
        assert ungranted.status_code == 403
        assert "no grant exists" in ungranted.json()["reason"]

        # an operation nobody declared is a sealed BLOCK too, decided first
        undeclared = client.post(
            "/v1/decide", json=decide_json("operator", "fs.chmod"), headers=headers
        )
        assert undeclared.status_code == 403
        assert undeclared.json()["triggered_by"] == "operation_registry"
        assert undeclared.json()["record"]["decision"] == "block"


def test_refuses_to_overwrite(provisioned, capsys):
    out, _ = provisioned
    assert isp.main(["--out", str(out)]) == 1
    assert "refusing to overwrite" in capsys.readouterr().err


def test_replace_existing_rotates_every_key(provisioned):
    out, _ = provisioned
    before = (out / "trust-bundle.json").read_text(encoding="utf-8")
    assert isp.main(["--out", str(out), "--replace-existing"]) == 0
    assert (out / "trust-bundle.json").read_text(encoding="utf-8") != before


def test_bundle_separates_minting_from_witnessing(provisioned):
    out, _ = provisioned
    bundle = json.loads((out / "trust-bundle.json").read_text(encoding="utf-8"))
    by_usage = {u: k["key_id"] for k in bundle["keys"] for u in k["usages"]}
    assert (
        by_usage["execution_authorization_signer"]
        != by_usage["dispatch_witness_signer"]
    )


def test_bad_grant_argument_is_rejected(tmp_path):
    with pytest.raises(SystemExit):
        isp.main(["--out", str(tmp_path / "x"), "--grant", "no-equals-sign"])
