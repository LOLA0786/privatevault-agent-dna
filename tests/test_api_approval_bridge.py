"""Approval bridge over HTTP (ADR 0020): /v1/decide accepts a signed approval
and /v1/authorize binds the permit to it.

Claims -> tests:
  - A verified approval turns a 202 into a 200 whose record names the
    artifact digest; the permit carries the same digest
    -> test_approved_decide_mints_a_permit_bound_to_the_approval
  - /v1/authorize refuses a permit whose approval digest differs from the
    sealed record, or is absent
    -> test_authorize_requires_the_sealed_approval_digest
  - Reuse: the same approval cannot produce a second ALLOW or a second permit
    -> test_approval_reuse_yields_no_second_permit
  - Without PV_APPROVER_TRUST_BUNDLE an approval block is refused outright
    -> test_approval_block_refused_when_no_bundle_is_pinned
  - Separation of duties through the API: approver equal to the agent
    -> test_self_approval_is_refused
  - An approval on an audit-only decide is refused outright
    -> test_approval_on_audit_only_decide_is_refused
"""

from __future__ import annotations

import json

import pytest

from agent_dna.approval_v01 import approval_artifact_digest
from tests.approval_world import ApproverWorld
from tests.decide_binding import decide_json, dispatch_context_for
from tests.test_authorize_mint_claim import AGENT, ORG, _authorize_body, build_mint_env

CAP = "payments.pay_invoice"
WIRE = b'{"amount":18000,"currency":"INR","payee_id":"V-100"}'
PEER = b"tls-spki:payments.partner.example"


def _execution_action(amount: int = 18000) -> dict:
    return {
        "subject_principal": f"{AGENT}@{ORG}",
        "subject_key_id": AGENT,
        "action": CAP,
        "resource": "vendor:V-100",
        "parameters": {"amount": amount, "currency": "INR", "payee_id": "V-100"},
    }


def _dispatch() -> dict:
    return {
        "transport": "https",
        "destination": "payments.partner.example",
        "operation": "POST /api/v1/transfers",
        "wire_content_type": "application/json",
        "wire_content_encoding": "identity",
        "tool_id": "payments.transfers.v1",
        "tool_schema_digest": "sha256:" + "0" * 64,
        "tool_artifact_digest": "sha256:" + "1" * 64,
        "credential_audience": "payments.partner.example",
        "idempotency_key_digest": "sha256:" + "0" * 64,
        "retry_policy_digest": "sha256:" + "1" * 64,
        "serialization": "pv-json-parameters/0.1",
    }


@pytest.fixture
def world(tmp_path, monkeypatch):
    approver = ApproverWorld(ORG)
    bundle_path = tmp_path / "approvers.json"
    bundle_path.write_text(json.dumps(approver.bundle), encoding="utf-8")
    monkeypatch.setenv("PV_APPROVER_TRUST_BUNDLE", str(bundle_path))
    gen = build_mint_env(tmp_path, monkeypatch)
    env = next(gen)
    env["approver"] = approver
    try:
        yield env
    finally:
        gen.close()


def _decide(client, key, approval=None, *, bound=True, amount=18000):
    body = decide_json(
        AGENT,
        CAP,
        arguments={"amount": amount, "currency": "INR", "payee_id": "V-100"},
        resource="vendor:V-100",
        org=ORG,
        dispatch_context=dispatch_context_for(
            adapter="https",
            transport="https",
            operation="POST /api/v1/transfers",
            destination="payments.partner.example",
            wire_content_type="application/json",
        )
        if bound
        else None,
    )
    if bound:
        body["execution_action"] = _execution_action(amount)
    else:
        body.pop("execution_action", None)
        body.pop("dispatch_context", None)
    body["request_id"] = "req-inv-1"
    if approval is not None:
        body["approval"] = approval
    return client.post("/v1/decide", headers={"X-API-Key": key}, json=body)


def test_approved_decide_mints_a_permit_bound_to_the_approval(world):
    client, key, approver = world["client"], world["key"], world["approver"]
    plain = _decide(client, key)
    assert plain.status_code == 202, plain.text

    approval = approver.approve(_execution_action(), request_id="req-inv-1")
    digest = approval_artifact_digest(approval["artifact"])
    approved = _decide(client, key, approval)
    assert approved.status_code == 200, approved.text
    record = approved.json()["record"]
    assert record["decision"] == "allow"
    assert record["triggered_by"] == "approval"
    assert record["approval_ref"] == digest

    body = _authorize_body(
        record, wire=WIRE, peer=PEER, dispatch=_dispatch(), action=_execution_action()
    )
    body["approval_artifact_digest"] = digest
    minted = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
    assert minted.status_code == 200, minted.text
    assert minted.json()["authorization"]["approval_artifact_digest"] == digest


def test_authorize_requires_the_sealed_approval_digest(world):
    client, key, approver = world["client"], world["key"], world["approver"]
    approval = approver.approve(_execution_action(), request_id="req-inv-1")
    record = _decide(client, key, approval).json()["record"]
    base = _authorize_body(
        record, wire=WIRE, peer=PEER, dispatch=_dispatch(), action=_execution_action()
    )
    wrong = dict(base, approval_artifact_digest="sha256:" + "a" * 64)
    r = client.post("/v1/authorize", headers={"X-API-Key": key}, json=wrong)
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["reason_code"] == "AUTHORIZE_APPROVAL_MISMATCH"
    absent = dict(base, approval_artifact_digest=None)
    r = client.post("/v1/authorize", headers={"X-API-Key": key}, json=absent)
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["reason_code"] == "AUTHORIZE_APPROVAL_MISMATCH"


def test_approval_reuse_yields_no_second_permit(world):
    client, key, approver = world["client"], world["key"], world["approver"]
    approval = approver.approve(_execution_action(), request_id="req-inv-1")
    first = _decide(client, key, approval)
    assert first.status_code == 200, first.text
    second = _decide(client, key, approval)
    assert second.status_code == 202, second.text
    assert "APPROVAL_ALREADY_USED" in second.json()["reason"]
    record = second.json()["record"]
    body = _authorize_body(
        record, wire=WIRE, peer=PEER, dispatch=_dispatch(), action=_execution_action()
    )
    body["approval_artifact_digest"] = approval_artifact_digest(approval["artifact"])
    r = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
    assert r.status_code == 403, r.text
    assert "authorization" not in r.json()


def test_approval_block_refused_when_no_bundle_is_pinned(tmp_path, monkeypatch):
    monkeypatch.delenv("PV_APPROVER_TRUST_BUNDLE", raising=False)
    gen = build_mint_env(tmp_path, monkeypatch)
    env = next(gen)
    try:
        approver = ApproverWorld(ORG)
        approval = approver.approve(_execution_action(), request_id="req-inv-1")
        r = _decide(env["client"], env["key"], approval)
        assert r.status_code == 422, r.text
        assert r.json()["detail"]["reason_code"] == "APPROVAL_NOT_CONFIGURED"
        assert "record" not in r.json()
    finally:
        gen.close()


def test_self_approval_is_refused(world):
    client, key = world["client"], world["key"]
    selfie = ApproverWorld(
        ORG, approver_principal=f"{AGENT}@{ORG}", approver_key_id="self"
    )
    # Not pinned either, but the identity rule must be stated on its own:
    # pin this bundle instead and still refuse.
    import json as _json

    bundle_path = world["bundle_path"].parent / "self-approvers.json"
    bundle_path.write_text(_json.dumps(selfie.bundle), encoding="utf-8")
    from agent_dna.approval_bridge import ApprovalBridge

    engine = world["server"].state["engine"]
    inner = getattr(engine, "engine", engine)
    inner.approvals = ApprovalBridge(
        trust_bundle=selfie.bundle, ledger=world["server"].state["store"]
    )
    approval = selfie.approve(_execution_action(), request_id="req-inv-1")
    r = _decide(client, key, approval)
    assert r.status_code == 202, r.text
    assert "APPROVAL_SEPARATION_OF_DUTIES" in r.json()["reason"]


def test_approval_on_audit_only_decide_is_refused(world):
    client, key, approver = world["client"], world["key"], world["approver"]
    approval = approver.approve(_execution_action(), request_id="req-inv-1")
    r = _decide(client, key, approval, bound=False)
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["reason_code"] == "APPROVAL_REQUIRES_BOUND_DECISION"
