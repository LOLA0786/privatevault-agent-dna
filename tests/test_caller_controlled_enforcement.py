"""Adversarial: callers cannot skip operator-configured enforcement (F-03/04/05)."""

from __future__ import annotations

import importlib
import json
import time

import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.apikeys import generate_key
from agent_dna.authority_v01 import (
    CANONICALIZATION,
    TRUST_SPEC,
    encode_public_key,
)
from agent_dna.composition import RuntimeConfig, build_production_runtime
from agent_dna.control_posture import (
    AUTHORIZATION_NOT_CONFIGURED,
    AUTHORIZE_LOOP_EVENTS_REQUIRED,
    CROSS_AGENT_EXECUTION_ID_REQUIRED,
    posture_from_evidence,
)
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.execution_v01 import sha256_bytes_digest
from agent_dna.grants import GrantRegistry
from agent_dna.open_authorizer import OpenAuthorizer
from agent_dna.trace import AgentAction


class _StubScorer:
    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.0,
            severity=Severity.INFO,
            reasons=[],
        )


def test_f05_decision_engine_without_authorizer_is_not_allow():
    engine = DecisionEngine(scorer=_StubScorer())
    result = engine.decide(
        AgentAction(
            agent_id="a1",
            capability="crm.read_contact",
            timestamp=time.time(),
        )
    )
    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.triggered_by == "authorization"
    assert AUTHORIZATION_NOT_CONFIGURED in result.reason


def test_f05_production_composition_deny_all_without_grants_file(tmp_path, monkeypatch):
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    monkeypatch.delenv("PV_GRANTS_FILE", raising=False)
    rt = build_production_runtime(RuntimeConfig(db_path=str(tmp_path / "pv.db")))
    assert rt.composition["authorization"]["mode"] == "deny_all"
    assert isinstance(rt.engine.authorizer, GrantRegistry)
    result = rt.monitor().process(
        AgentAction(
            agent_id="prod-agent",
            capability="crm.read_contact",
            timestamp=time.time(),
        )
    )
    assert result.decision == Decision.REQUIRE_APPROVAL
    assert result.triggered_by == "authorization"
    assert "no grant exists" in result.reason


def test_f05_open_authorizer_only_under_allow_no_auth(tmp_path, monkeypatch):
    monkeypatch.setenv("PV_ALLOW_NO_AUTH", "1")
    rt = build_production_runtime(RuntimeConfig(db_path=str(tmp_path / "open.db")))
    assert rt.composition["authorization"]["mode"] == "open"
    assert isinstance(rt.engine.authorizer, OpenAuthorizer)


@pytest.fixture()
def production_api(tmp_path, monkeypatch):
    """Auth on, grants unset, require-mode flags on (platform-like)."""
    op = generate_key("maker-1", "full")
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
        "organisation_id": "org-demo",
        "bundle_version": 1,
        "pinned_at": "2026-07-31T11:00:00Z",
        "keys": [
            {
                "key_id": "k1",
                "principal": "execution-runtime@org-demo",
                "algorithm": "ed25519",
                "public_key": encode_public_key(sk),
                "usages": ["execution_authorization_signer"],
            }
        ],
    }
    bundle_path = tmp_path / "trust.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "pv.db"))
    monkeypatch.setenv("PV_API_KEYS_FILE", str(keys_path))
    monkeypatch.setenv("PV_EXECUTION_SIGNER_KEY", str(key_path))
    monkeypatch.setenv("PV_TRUST_BUNDLE", str(bundle_path))
    monkeypatch.setenv("PV_CROSS_AGENT", "1")
    monkeypatch.setenv("PV_CROSS_AGENT_REQUIRE_EXECUTION_ID", "1")
    monkeypatch.setenv("PV_LOOP_EVENTS_REQUIRED", "1")
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    monkeypatch.delenv("PV_GRANTS_FILE", raising=False)

    import api.server as server

    server._pv_signer_cache.clear()
    importlib.reload(server)
    server._pv_signer_cache.clear()
    with TestClient(server.app) as client:
        yield client, op["key"], server


def test_f03_require_execution_id_blocks_uncorrelated_payment(production_api):
    client, key, server = production_api
    # Grant so authorization is not the refusing layer.
    reg = GrantRegistry()
    reg.authorization_mode = "grants_file"
    reg.grant(
        agent_id="maker-1",
        capability="payments.initiate_wire",
        granted_by="test",
    )
    reg.grant(
        agent_id="maker-1",
        capability="payments.approve_wire",
        granted_by="test",
    )
    server.state["engine"].authorizer = reg

    first = client.post(
        "/v1/decide",
        headers={"X-API-Key": key},
        json={
            "agent_id": "maker-1",
            "capability": "payments.initiate_wire",
            "timestamp": time.time(),
            "arguments": {"amount": 1000},
        },
    )
    assert first.status_code == 403, first.text
    body = first.json()
    assert body["decision"] == "block"
    assert body["triggered_by"] == "cross_agent_correlation"
    assert CROSS_AGENT_EXECUTION_ID_REQUIRED in body["reason"]
    posture = posture_from_evidence(body["record"]["evidence"])
    assert posture is not None
    assert posture["cross_agent_require_execution_id"] is True
    assert posture["cross_agent_correlated"] is False


def test_f03_require_mode_off_preserves_skip_and_records_it(tmp_path, monkeypatch):
    op = generate_key("maker-1", "full")
    keys_path = tmp_path / "keys.json"
    keys_path.write_text(
        json.dumps({op["hash"]: {"name": op["name"], "scope": "full"}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "pv.db"))
    monkeypatch.setenv("PV_API_KEYS_FILE", str(keys_path))
    monkeypatch.setenv("PV_CROSS_AGENT", "1")
    monkeypatch.setenv("PV_CROSS_AGENT_REQUIRE_EXECUTION_ID", "0")
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    # Deny-all would mask the correlation test; attach grants for payments.
    grants_path = tmp_path / "grants.json"
    grants_path.write_text(
        json.dumps(
            [
                {
                    "agent_id": "maker-1",
                    "capability": "payments.initiate_wire",
                    "granted_by": "test",
                },
                {
                    "agent_id": "maker-1",
                    "capability": "payments.approve_wire",
                    "granted_by": "test",
                },
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("PV_GRANTS_FILE", str(grants_path))

    import api.server as server

    importlib.reload(server)
    with TestClient(server.app) as client:
        r = client.post(
            "/v1/decide",
            headers={"X-API-Key": op["key"]},
            json={
                "agent_id": "maker-1",
                "capability": "payments.initiate_wire",
                "timestamp": time.time(),
                "arguments": {"amount": 1000},
            },
        )
        assert r.status_code in (200, 202), r.text
        assert r.json().get("triggered_by") != "cross_agent_correlation"
        posture = posture_from_evidence(r.json()["record"]["evidence"])
        assert posture is not None
        assert posture["cross_agent_require_execution_id"] is False
        assert posture["cross_agent_correlated"] is False
        assert posture["authorization_mode"] == "grants_file"


def test_f04_authorize_without_events_refused_when_required(production_api):
    client, key, server = production_api
    # Decide under open grant injection so we can reach authorize mint path.
    reg = GrantRegistry()
    reg.authorization_mode = "grants_file"
    reg.grant(
        agent_id="maker-1",
        capability="crm.read_contact",
        granted_by="test",
    )
    server.state["engine"].authorizer = reg

    decided = client.post(
        "/v1/decide",
        headers={"X-API-Key": key},
        json={
            "agent_id": "maker-1",
            "capability": "crm.read_contact",
            "timestamp": time.time(),
            "arguments": {"note": "loop"},
            "execution_id": "exec-loop-1",
            # Mintable DRP 0.2 binding: without it authorize refuses on
            # protocol version before the loop gate is reached, and this
            # test is about the loop gate.
            "execution_action": {
                "subject_principal": "maker-1@org-demo",
                "subject_key_id": "maker-1",
                "action": "crm.read_contact",
                "resource": "crm:contact",
                "parameters": {"note": "loop"},
            },
            "dispatch_context": {
                "adapter": "https",
                "transport": "https",
                "operation": "GET /v1/contacts",
                "destination": "crm.example",
                "wire_content_type": "application/json",
            },
        },
    )
    # crm.read_contact with grant may still be allow/approval from drift
    assert decided.status_code in (200, 202), decided.text
    record = decided.json()["record"]
    if decided.json()["decision"] != "allow":
        pytest.skip("drift required approval; authorize binding needs ALLOW")

    digest = "sha256:" + ("ab" * 32)
    z = "sha256:" + ("0" * 64)
    one = "sha256:" + ("1" * 64)
    wire = b'{"ok":true}'
    body = {
        "request_id": "req-1",
        "agent_id": "maker-1",
        "organisation_id": "org-demo",
        "decision_id": record["decision_id"],
        "action": {
            "subject_principal": "maker-1@org-demo",
            "subject_key_id": "maker-1",
            "action": "crm.read_contact",
            "resource": "crm:contact",
            "parameters": {"note": "loop"},
        },
        "dispatch": {
            "transport": "https",
            "destination": "crm.example",
            "operation": "GET /v1/contacts",
            "wire_content_type": "application/json",
            "wire_content_encoding": "identity",
            "tool_id": "crm.read_contact.v1",
            "tool_schema_digest": z,
            "tool_artifact_digest": one,
            "credential_audience": "crm.example",
            "idempotency_key_digest": z,
            "retry_policy_digest": one,
        },
        "expected_wire_bytes_digest": sha256_bytes_digest(wire),
        "expected_wire_bytes_length": len(wire),
        "expected_peer_identity_digest": digest,
        "decision_receipt_digest": "sha256:" + record["record_hash"],
        "authority_receipt_digest": one,
        "state_snapshot_digest": z,
        "policy_bundle_digest": one,
        "obligations_digest": z,
    }
    r = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["reason_code"] == AUTHORIZE_LOOP_EVENTS_REQUIRED
    assert "authorization" not in r.json()


def test_control_posture_in_decision_record(production_api):
    client, key, server = production_api
    reg = GrantRegistry()
    reg.authorization_mode = "grants_file"
    reg.grant(
        agent_id="maker-1",
        capability="crm.read_contact",
        granted_by="test",
    )
    server.state["engine"].authorizer = reg
    r = client.post(
        "/v1/decide",
        headers={"X-API-Key": key},
        json={
            "agent_id": "maker-1",
            "capability": "crm.read_contact",
            "timestamp": time.time(),
            "execution_id": "exec-posture-1",
        },
    )
    assert r.status_code in (200, 202, 403)
    posture = posture_from_evidence(r.json()["record"]["evidence"])
    assert posture is not None
    assert "authorization_mode" in posture
    assert posture["cross_agent_require_execution_id"] is True
    assert posture["loop_events_required"] is True
    assert posture["cross_agent_correlated"] is True
