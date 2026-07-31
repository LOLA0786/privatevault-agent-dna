#!/usr/bin/env python3
"""Mint a permit through the real endpoint and verify it with the real verifier."""
from __future__ import annotations

import os
import sys

from agent_dna.execution_v01 import (
    sha256_bytes_digest,
    verify_execution_authorization,
)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from api.server import AuthorizeRequest, Principal, authorize  # noqa: E402

Z = "sha256:" + "0" * 64
ONE = "sha256:" + "1" * 64
WIRE = b'{"account":"4471","amount":400000,"currency":"INR"}'
PEER = b"tls-spki:payments.store.example:v3"
ORG = os.environ.get("PV_ORGANISATION_ID", "store.example")

action = {
    "subject_principal": f"refund-agent@{ORG}",
    "subject_key_id": "refund-agent-01",
    "action": "payments.refund",
    "resource": "account:4471",
    "parameters": {"case_id": "case-7821"},
}
dispatch = {
    "transport": "https",
    "destination": "payments.store.example",
    "operation": "POST /v1/refunds",
    "wire_content_type": "application/json",
    "wire_content_encoding": "identity",
    "tool_id": "payments.refund.v3",
    "tool_schema_digest": Z,
    "tool_artifact_digest": ONE,
    "credential_audience": "payments.store.example",
    "idempotency_key_digest": Z,
    "retry_policy_digest": ONE,
}

req = AuthorizeRequest(
    request_id="request-001",
    agent_id="refund-agent-01",
    organisation_id=ORG,
    action=action,
    dispatch=dispatch,
    expected_wire_bytes_digest=sha256_bytes_digest(WIRE),
    expected_wire_bytes_length=len(WIRE),
    expected_peer_identity_digest=sha256_bytes_digest(PEER),
    decision_receipt_digest=Z,
    authority_receipt_digest=ONE,
    approval_artifact_digest=Z,
    state_snapshot_digest=Z,
    policy_bundle_digest=ONE,
    obligations_digest=Z,
)

caller = Principal(agent_id="refund-agent-01", scope="full")
result = authorize(req, caller)

authorization = result["authorization"]
trust_bundle = result["trust_bundle"]

report = verify_execution_authorization(
    authorization,
    trust_bundle,
    expected_request_id="request-001",
    expected_action=action,
    expected_dispatch=dispatch,
    expected_decision_receipt_digest=Z,
    expected_authority_receipt_digest=ONE,
    expected_approval_artifact_digest=Z,
    expected_state_snapshot_digest=Z,
    expected_policy_bundle_digest=ONE,
    expected_obligations_digest=Z,
    expected_wire_bytes=WIRE,
    expected_peer_identity_bytes=PEER,
    at_time=result["at_time"],
    already_consumed=False,
)

print("permit id   :", authorization["execution_authorization_id"])
print("max_uses    :", authorization["max_uses"])
print("signer      :", authorization["signer_key_id"])
print("verifies    :", report.ok, "|", report.evidence_state, "|", report.decision_conformance)

tampered = verify_execution_authorization(
    authorization,
    trust_bundle,
    expected_request_id="request-001",
    expected_action=action,
    expected_dispatch=dispatch,
    expected_decision_receipt_digest=Z,
    expected_authority_receipt_digest=ONE,
    expected_approval_artifact_digest=Z,
    expected_state_snapshot_digest=Z,
    expected_policy_bundle_digest=ONE,
    expected_obligations_digest=Z,
    expected_wire_bytes=b'{"account":"4471","amount":900000}',
    expected_peer_identity_bytes=PEER,
    at_time=result["at_time"],
    already_consumed=False,
)
print("tampered    :", tampered.ok, "|", tampered.evidence_state)

if not report.ok or tampered.ok:
    sys.exit("SMOKE TEST FAILED")
print("\nOK - permit binds exact bytes and rejects substitution")
