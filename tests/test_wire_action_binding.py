"""Action parameters and wire bytes must be the same purchase under a named serializer."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from agent_dna.apikeys import generate_key
from agent_dna.authority_v01 import (
    CANONICALIZATION,
    TRUST_SPEC,
    encode_public_key,
)
from agent_dna.authorize_binding import AUTHORIZE_WIRE_ACTION_MISMATCH
from agent_dna.execution_v01 import sha256_bytes_digest
from agent_dna.wire_serialization_v01 import WIRE_SERIALIZATION_JSON_PARAMETERS_V01
from tests.decide_binding import decide_json, dispatch_context_for, execution_action_for

Z = "sha256:" + ("0" * 64)
ONE = "sha256:" + ("1" * 64)
ORG = "org-demo"
AGENT = "buyer-agent"
CAP = "procurement.po.create"
ARGS40 = {"material": "HR-COIL-3MM", "quantity_tonnes": 40, "vendor_id": "V-001"}
ARGS400 = {**ARGS40, "quantity_tonnes": 400}
PEER = b"tls-spki:erp-sandbox.example:v1"


def _canon(payload: dict) -> bytes:
    return json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


WIRE40 = _canon(ARGS40)
WIRE400 = _canon(ARGS400)


@pytest.fixture()
def env(tmp_path, monkeypatch):
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
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "pv.db"))
    monkeypatch.setenv("PV_API_KEYS_FILE", str(keys_path))
    monkeypatch.setenv("PV_EXECUTION_SIGNER_KEY", str(key_path))
    monkeypatch.setenv("PV_TRUST_BUNDLE", str(bundle_path))
    monkeypatch.setenv("PV_BASELINE_CAPABILITIES", CAP)
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)

    import importlib

    import api.server as server

    server._pv_signer_cache.clear()
    importlib.reload(server)
    server._pv_signer_cache.clear()
    with TestClient(server.app) as client:
        from agent_dna.grants import GrantRegistry

        reg = GrantRegistry()
        reg.authorization_mode = "grants_file"
        reg.grant(agent_id=AGENT, capability=CAP, granted_by="test")
        server.state["engine"].authorizer = reg
        yield {"client": client, "key": op["key"], "server": server}


def _dispatch():
    ctx = dispatch_context_for(
        operation="POST /v1/purchase-orders",
        destination="erp-sandbox.example",
        serialization=WIRE_SERIALIZATION_JSON_PARAMETERS_V01,
    )
    return {
        "transport": ctx["transport"],
        "destination": ctx["destination"],
        "operation": ctx["operation"],
        "wire_content_type": ctx["wire_content_type"],
        "wire_content_encoding": "identity",
        "tool_id": "procurement.po.create.v1",
        "tool_schema_digest": Z,
        "tool_artifact_digest": ONE,
        "credential_audience": ctx["destination"],
        "idempotency_key_digest": Z,
        "retry_policy_digest": ONE,
        "serialization": ctx["serialization"],
    }


def _authorize(client, key, record, *, action=None, wire=WIRE40, dispatch=None):
    body = {
        "request_id": "req-wire-1",
        "agent_id": AGENT,
        "organisation_id": ORG,
        "decision_id": record["decision_id"],
        "action": action
        or execution_action_for(
            AGENT, CAP, ARGS40, resource="erp-sandbox.example", org=ORG
        ),
        "dispatch": _dispatch() if dispatch is None else dispatch,
        "expected_wire_bytes_digest": sha256_bytes_digest(wire),
        "expected_wire_bytes_length": len(wire),
        "expected_peer_identity_digest": sha256_bytes_digest(PEER),
        "decision_receipt_digest": "sha256:" + record["record_hash"],
        "authority_receipt_digest": ONE,
        "state_snapshot_digest": Z,
        "policy_bundle_digest": ONE,
        "obligations_digest": Z,
    }
    return client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)


def test_first_mint_refuses_action_40_with_wire_400(env):
    client, key = env["client"], env["key"]
    decided = client.post(
        "/v1/decide",
        headers={"X-API-Key": key},
        json=decide_json(
            AGENT,
            CAP,
            arguments=dict(ARGS40),
            resource="erp-sandbox.example",
            org=ORG,
            dispatch_context=dispatch_context_for(
                operation="POST /v1/purchase-orders",
                destination="erp-sandbox.example",
            ),
            expected_wire_bytes_digest=sha256_bytes_digest(WIRE40),
            expected_wire_bytes_length=len(WIRE40),
        ),
    )
    assert decided.status_code == 200, decided.text
    record = decided.json()["record"]

    refused = _authorize(client, key, record, wire=WIRE400)
    assert refused.status_code == 403, refused.text
    assert refused.json()["detail"]["reason_code"] == AUTHORIZE_WIRE_ACTION_MISMATCH
    assert "execution_authorization_id" not in json.dumps(refused.json())


def test_decide_refuses_inconsistent_action_and_wire_on_first_request(env):
    client, key = env["client"], env["key"]
    decided = client.post(
        "/v1/decide",
        headers={"X-API-Key": key},
        json=decide_json(
            AGENT,
            CAP,
            arguments=dict(ARGS40),
            resource="erp-sandbox.example",
            org=ORG,
            dispatch_context=dispatch_context_for(
                operation="POST /v1/purchase-orders",
                destination="erp-sandbox.example",
            ),
            expected_wire_bytes_digest=sha256_bytes_digest(WIRE400),
            expected_wire_bytes_length=len(WIRE400),
        ),
    )
    assert decided.status_code == 422, decided.text
    assert "expected_wire_bytes_digest does not match" in decided.text


def test_consistent_action_and_wire_still_mints(env):
    client, key = env["client"], env["key"]
    decided = client.post(
        "/v1/decide",
        headers={"X-API-Key": key},
        json=decide_json(
            AGENT,
            CAP,
            arguments=dict(ARGS40),
            resource="erp-sandbox.example",
            org=ORG,
            dispatch_context=dispatch_context_for(
                operation="POST /v1/purchase-orders",
                destination="erp-sandbox.example",
            ),
            expected_wire_bytes_digest=sha256_bytes_digest(WIRE40),
            expected_wire_bytes_length=len(WIRE40),
        ),
    )
    assert decided.status_code == 200, decided.text
    record = decided.json()["record"]
    minted = _authorize(client, key, record, wire=WIRE40)
    assert minted.status_code == 200, minted.text
    assert minted.json()["authorization"]["execution_authorization_id"]


@pytest.mark.parametrize("serialization", ["pv-audit-only/0.1", "unknown/0.1", None])
def test_decide_rejects_non_mintable_serialization(env, serialization):
    context = dispatch_context_for()
    if serialization is None:
        del context["serialization"]
    else:
        context["serialization"] = serialization
    response = env["client"].post(
        "/v1/decide",
        headers={"X-API-Key": env["key"]},
        json=decide_json(AGENT, CAP, arguments=ARGS40, dispatch_context=context),
    )
    assert response.status_code == 422


@pytest.mark.parametrize(
    ("serialization", "reason"),
    [
        ("pv-audit-only/0.1", "AUTHORIZE_WIRE_SERIALIZATION_UNKNOWN"),
        ("pv-json-parameters/0.1", "AUTHORIZE_DISPATCH_CONTEXT_DIGEST_MISMATCH"),
    ],
)
def test_connector_record_cannot_be_upgraded_to_a_permit(env, serialization, reason):
    from agent_dna.connector import ToolCallRequest
    from agent_dna.dispatch_context_v01 import (
        AUDIT_ONLY_SERIALIZATION,
        dispatch_context_digest,
    )

    runtime = env["server"].state["runtime"]
    verdict = runtime.middleware().handle(
        ToolCallRequest(
            adapter="https",
            tool=CAP,
            api_key=env["key"],
            arguments=ARGS40,
            context={
                "subject_principal": f"{AGENT}@{ORG}",
                "resource": "erp-sandbox.example",
                "destination": "erp-sandbox.example",
                "serialization": "pv-json-parameters/0.1",
            },
        )
    )
    assert verdict.decision == "allow"
    record = next(
        r for r in runtime.recorder.graph if r.record_hash == verdict.record_hash
    )
    assert record.verify()
    assert record.dispatch_context_digest == dispatch_context_digest(
        dispatch_context_for(
            operation=CAP,
            destination="erp-sandbox.example",
            serialization=AUDIT_ONLY_SERIALIZATION,
        )
    )
    dispatch = {**_dispatch(), "operation": CAP, "serialization": serialization}
    response = _authorize(
        env["client"], env["key"], record.to_dict(), dispatch=dispatch
    )
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["reason_code"] == reason
    assert "execution_authorization_id" not in response.text


def test_legacy_context_digest_is_read_only_and_byte_stable():
    from agent_dna.authority_v01 import AuthorityFormatError
    from agent_dna.dispatch_context_v01 import (
        dispatch_context_digest,
        legacy_dispatch_context_digest,
        validate_dispatch_context,
    )

    context = dispatch_context_for()
    del context["serialization"]
    digest = "sha256:38b95de2bff01a824554f7502473af13f55673ccbb1304a6c804e0de4b50bdf1"
    assert legacy_dispatch_context_digest(context) == digest
    assert "serialization" not in context
    with pytest.raises(AuthorityFormatError):
        validate_dispatch_context(context)
    with pytest.raises(AuthorityFormatError):
        dispatch_context_digest(context)
    with pytest.raises(AuthorityFormatError):
        legacy_dispatch_context_digest(
            {**context, "serialization": "pv-json-parameters/0.1"}
        )
    assert dispatch_context_digest(dispatch_context_for()) != digest


@pytest.mark.parametrize("serialization", ["pv-audit-only/0.1", "unknown/0.1"])
def test_runtime_validators_match_serializer_schema(serialization):
    from agent_dna.authority_v01 import AuthorityFormatError
    from agent_dna.dispatch_v01 import _validate_observed_dispatch
    from agent_dna.execution_v01 import sign_execution_authorization
    from tests.test_execution_v01 import _unsigned_authorization

    authorization = _unsigned_authorization()
    authorization["dispatch"]["serialization"] = serialization
    with pytest.raises(AuthorityFormatError, match="unknown wire serialization"):
        sign_execution_authorization(authorization, SigningKey.generate())
    with pytest.raises(AuthorityFormatError, match="unknown wire serialization"):
        _validate_observed_dispatch(authorization["dispatch"])
