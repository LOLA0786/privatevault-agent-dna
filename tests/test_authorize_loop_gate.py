"""Loop discovery refuses /v1/authorize when security_events BLOCK."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from agent_dna.apikeys import generate_key


@pytest.fixture()
def authorize_client(tmp_path, monkeypatch):
    op = generate_key("treasury-agent", "full")
    keys_path = tmp_path / "keys.json"
    keys_path.write_text(
        json.dumps({op["hash"]: {"name": op["name"], "scope": "full"}}),
        encoding="utf-8",
    )
    sk = SigningKey.generate()
    key_path = tmp_path / "exec.key"
    key_path.write_bytes(bytes(sk))
    bundle = {
        "organisation_id": "org-demo",
        "keys": [
            {
                "key_id": "k1",
                "public_key": sk.verify_key.encode().hex(),
            }
        ],
    }
    bundle_path = tmp_path / "trust.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "pv.db"))
    monkeypatch.setenv("PV_API_KEYS_FILE", str(keys_path))
    monkeypatch.setenv("PV_EXECUTION_SIGNER_KEY", str(key_path))
    monkeypatch.setenv("PV_TRUST_BUNDLE", str(bundle_path))
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)

    import api.server as server

    # Clear signer cache between tests/reloads
    server._pv_signer_cache.clear()
    importlib.reload(server)
    server._pv_signer_cache.clear()

    with TestClient(server.app) as client:
        yield client, op["key"]


def _base_body():
    digest = "sha256:" + ("ab" * 32)
    return {
        "request_id": "req-1",
        "agent_id": "treasury-agent",
        "organisation_id": "org-demo",
        "action": {"capability": "payments.transfer"},
        "dispatch": {"channel": "wire"},
        "expected_wire_bytes_digest": digest,
        "expected_wire_bytes_length": 12,
        "expected_peer_identity_digest": digest,
        "decision_receipt_digest": digest,
        "authority_receipt_digest": digest,
        "state_snapshot_digest": digest,
        "policy_bundle_digest": digest,
        "obligations_digest": digest,
    }


def test_circular_authority_refuses_authorize(authorize_client):
    client, key = authorize_client
    events = [
        json.loads(line)
        for line in (
            Path("examples/loop_discovery/circular_authority.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
            if Path("examples/loop_discovery/circular_authority.jsonl").is_file()
            else []
        )
        if line.strip()
    ]
    assert events, "fixture missing"
    body = _base_body()
    body["security_events"] = events
    r = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
    assert r.status_code == 403
    detail = r.json()["detail"]
    assert detail["triggered_by"] == "loop_discovery"
    assert detail["decision"] in ("BLOCK", "REVIEW")
