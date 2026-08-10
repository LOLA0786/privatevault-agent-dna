"""Loop discovery refuses /v1/authorize when security_events BLOCK."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from agent_dna.apikeys import generate_key
from agent_dna.authority_v01 import (
    CANONICALIZATION,
    TRUST_SPEC,
    encode_public_key,
)
from agent_dna.execution_v01 import sha256_bytes_digest
from tests.decide_binding import decide_json, dispatch_context_for

Z = "sha256:" + ("0" * 64)
ONE = "sha256:" + ("1" * 64)
WIRE = b'{"account":"4471","amount":400000,"currency":"INR"}'
PEER = b"tls-spki:payments.store.example:v3"
ORG = "org-demo"
AGENT = "treasury-agent"
ARGS = {"note": "loop-gate"}


@pytest.fixture()
def authorize_client(tmp_path, monkeypatch):
    op = generate_key(AGENT, "full")
    keys_path = tmp_path / "keys.json"
    keys_path.write_text(
        json.dumps({op["hash"]: {"name": op["name"], "scope": "full"}}),
        encoding="utf-8",
    )
    sk = SigningKey.generate()
    key_path = tmp_path / "exec.key"
    key_path.write_bytes(bytes(sk))
    bundle = {
        "spec": TRUST_SPEC,
        "canonicalization": CANONICALIZATION,
        "organisation_id": ORG,
        "bundle_version": 1,
        "pinned_at": "2026-07-31T11:00:00Z",
        "keys": [
            {
                "key_id": "k1",
                "principal": f"execution-runtime@{ORG}",
                "algorithm": "ed25519",
                "public_key": encode_public_key(sk),
                "usages": ["execution_authorization_signer"],
            }
        ],
    }
    bundle_path = tmp_path / "trust.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    grants_path = tmp_path / "grants.json"
    grants_path.write_text(
        json.dumps(
            [
                {
                    "agent_id": AGENT,
                    "capability": "crm.read_contact",
                    "granted_by": "test",
                }
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "pv.db"))
    monkeypatch.setenv("PV_API_KEYS_FILE", str(keys_path))
    monkeypatch.setenv("PV_EXECUTION_SIGNER_KEY", str(key_path))
    monkeypatch.setenv("PV_TRUST_BUNDLE", str(bundle_path))
    monkeypatch.setenv("PV_GRANTS_FILE", str(grants_path))
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)

    import api.server as server

    # Clear signer cache between tests/reloads
    server._pv_signer_cache.clear()
    importlib.reload(server)
    server._pv_signer_cache.clear()

    with TestClient(server.app) as client:
        yield client, op["key"]


def _base_body(decision_id: str, receipt: str):
    return {
        "request_id": "req-1",
        "agent_id": AGENT,
        "organisation_id": ORG,
        "decision_id": decision_id,
        "action": {
            "subject_principal": f"{AGENT}@{ORG}",
            "subject_key_id": AGENT,
            "action": "crm.read_contact",
            "resource": "crm:contact",
            "parameters": dict(ARGS),
        },
        "dispatch": {
            "transport": "https",
            "destination": "crm.store.example",
            "operation": "GET /v1/contacts",
            "wire_content_type": "application/json",
            "wire_content_encoding": "identity",
            "tool_id": "crm.read_contact.v1",
            "tool_schema_digest": Z,
            "tool_artifact_digest": ONE,
            "credential_audience": "crm.store.example",
            "idempotency_key_digest": Z,
            "retry_policy_digest": ONE,
        },
        "expected_wire_bytes_digest": sha256_bytes_digest(WIRE),
        "expected_wire_bytes_length": len(WIRE),
        "expected_peer_identity_digest": sha256_bytes_digest(PEER),
        "decision_receipt_digest": receipt,
        "authority_receipt_digest": ONE,
        "state_snapshot_digest": Z,
        "policy_bundle_digest": ONE,
        "obligations_digest": Z,
    }


def test_circular_authority_refuses_authorize(authorize_client):
    client, key = authorize_client
    decided = client.post(
        "/v1/decide",
        headers={"X-API-Key": key},
        json=decide_json(
            AGENT,
            "crm.read_contact",
            arguments=dict(ARGS),
            resource="crm:contact",
            org=ORG,
            dispatch_context=dispatch_context_for(
                adapter="https",
                transport="https",
                operation="GET /v1/contacts",
                destination="crm.store.example",
                wire_content_type="application/json",
            ),
        ),
    )
    assert decided.status_code == 200, decided.text
    record = decided.json()["record"]
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
    body = _base_body(record["decision_id"], "sha256:" + record["record_hash"])
    body["security_events"] = events
    r = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
    assert r.status_code == 403
    detail = r.json()["detail"]
    assert detail["triggered_by"] == "loop_discovery"
    assert detail["decision"] in ("BLOCK", "REVIEW")
