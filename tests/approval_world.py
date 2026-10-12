"""Shared fixture: a real approver world for the approval bridge (ADR 0020).

Nothing here is mocked. The approver trust bundle carries a root authority,
the approver's own key (``approval_signer`` + ``subject``), and the receipt
signer that attests the approver's authority. ``approve()`` produces the
three artifacts the bridge consumes: the immutable approval request, the
signed approval artifact, and the approver's authority receipt whose grant
chain descends from the root.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from nacl.signing import SigningKey

from agent_dna.approval_v01 import (
    APPROVAL_ARTIFACT_SPEC,
    APPROVAL_AUTHORITY_ACTION,
    APPROVAL_REQUEST_SPEC,
    approval_request_digest,
    sign_approval_artifact,
)
from agent_dna.authority_v01 import (
    CANONICALIZATION,
    COMPOSITION_PROFILE,
    GRANT_SPEC,
    RECEIPT_SPEC,
    TRUST_SPEC,
    encode_public_key,
    receipt_digest,
    sha256_digest,
    sign_grant,
    sign_receipt,
)

ZERO = "sha256:" + "0" * 64
STAMP = "%Y-%m-%dT%H:%M:%SZ"


def rfc3339(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime(STAMP)


class ApproverWorld:
    """One organisation's approver side: keys, bundle, and a way to approve."""

    def __init__(
        self,
        organisation_id: str = "lender.example",
        approver_principal: str = "cfo@lender.example",
        approver_key_id: str = "approver-cfo",
    ) -> None:
        self.organisation_id = organisation_id
        self.approver_principal = approver_principal
        self.approver_key_id = approver_key_id
        self.root_key = SigningKey.generate()
        self.approver_key = SigningKey.generate()
        self.receipt_key = SigningKey.generate()
        self.bundle: dict[str, Any] = {
            "spec": TRUST_SPEC,
            "canonicalization": CANONICALIZATION,
            "organisation_id": organisation_id,
            "bundle_version": 1,
            "pinned_at": "2026-01-01T00:00:00Z",
            "keys": [
                {
                    "key_id": "owner-root",
                    "principal": f"owner@{organisation_id}",
                    "algorithm": "ed25519",
                    "public_key": encode_public_key(self.root_key),
                    "usages": ["root_authority", "grant_issuer"],
                },
                {
                    "key_id": approver_key_id,
                    "principal": approver_principal,
                    "algorithm": "ed25519",
                    "public_key": encode_public_key(self.approver_key),
                    "usages": ["approval_signer", "subject"],
                },
                {
                    "key_id": "approvals-runtime",
                    "principal": f"approvals-runtime@{organisation_id}",
                    "algorithm": "ed25519",
                    "public_key": encode_public_key(self.receipt_key),
                    "usages": ["receipt_signer"],
                },
            ],
        }
        self.root_grant = sign_grant(
            {
                "spec": GRANT_SPEC,
                "canonicalization": CANONICALIZATION,
                "grant_id": "g-approver",
                "organisation_id": organisation_id,
                "issuer_principal": f"owner@{organisation_id}",
                "issuer_key_id": "owner-root",
                "subject_principal": approver_principal,
                "subject_key_id": approver_key_id,
                "parent_grant_digest": None,
                "capabilities": [
                    {
                        "action": APPROVAL_AUTHORITY_ACTION,
                        "resource": "approval_request:*",
                        "constraints": [],
                        "obligations": [],
                    }
                ],
                "can_delegate": False,
                "remaining_depth": 1,
                "valid_from": "2026-01-01T00:00:00Z",
                "expires_at": "2030-01-01T00:00:00Z",
            },
            self.root_key,
        )

    def approve(
        self,
        execution_action: dict[str, Any],
        *,
        request_id: str,
        now: datetime | None = None,
        signing_key: SigningKey | None = None,
        approver_principal: str | None = None,
        approver_key_id: str | None = None,
        artifact_ttl_s: int = 300,
        decision: str = "APPROVE",
    ) -> dict[str, Any]:
        """Return ``{"request", "artifact", "approver_authority_receipt"}``.

        Override ``signing_key``/``approver_principal``/``approver_key_id``
        to forge an approval from a key the bundle does not pin. ``now`` is
        the moment the approval is minted; by default a few tens of seconds
        before the wall clock so the artifact is valid when presented.
        """
        moment = (now or datetime.now(UTC)).replace(microsecond=0)
        principal = approver_principal or self.approver_principal
        key_id = approver_key_id or self.approver_key_id
        key = signing_key or self.approver_key
        request = {
            "spec": APPROVAL_REQUEST_SPEC,
            "canonicalization": CANONICALIZATION,
            "approval_request_id": f"apr-{uuid.uuid4()}",
            "organisation_id": self.organisation_id,
            "request_id": request_id,
            "created_at": rfc3339(moment - timedelta(seconds=60)),
            "expires_at": rfc3339(moment + timedelta(seconds=600)),
            "nonce": uuid.uuid4().hex,
            "decision_input_digest": ZERO,
            "action": dict(execution_action),
            "action_digest": sha256_digest(execution_action),
            "evidence_manifest_digest": ZERO,
            "presentation_digest": ZERO,
            "approval_requirement_digest": ZERO,
        }
        request_digest = approval_request_digest(request)
        receipt = sign_receipt(
            {
                "spec": RECEIPT_SPEC,
                "canonicalization": CANONICALIZATION,
                "receipt_id": f"r-{uuid.uuid4()}",
                "organisation_id": self.organisation_id,
                "previous_receipt_hash": None,
                "request_id": request["approval_request_id"],
                "decision_timestamp": rfc3339(moment - timedelta(seconds=45)),
                "decision_input_digest": request_digest,
                "grant_chain": [self.root_grant],
                "requested": {
                    "subject_principal": principal,
                    "subject_key_id": key_id,
                    "action": APPROVAL_AUTHORITY_ACTION,
                    "resource": "approval_request:" + request["approval_request_id"],
                    "facts": {},
                },
                "authority_result": {
                    "verdict": "ALLOW",
                    "reason_code": "AUTHORITY_GRANTED",
                },
                "policy_result": {
                    "verdict": "ALLOW",
                    "policy_id": "APPROVALS-001",
                    "policy_version": "1.0",
                    "policy_digest": ZERO,
                },
                "composition_profile": COMPOSITION_PROFILE,
                "final_verdict": "ALLOW",
                "signer_key_id": "approvals-runtime",
            },
            self.receipt_key,
        )
        artifact = sign_approval_artifact(
            {
                "spec": APPROVAL_ARTIFACT_SPEC,
                "canonicalization": CANONICALIZATION,
                "approval_id": f"approval-{uuid.uuid4()}",
                "approval_request_id": request["approval_request_id"],
                "approval_request_digest": request_digest,
                "organisation_id": self.organisation_id,
                "request_id": request_id,
                "decision_input_digest": ZERO,
                "action_digest": request["action_digest"],
                "evidence_manifest_digest": ZERO,
                "presentation_digest": ZERO,
                "approval_requirement_digest": ZERO,
                "approver_principal": principal,
                "approver_key_id": key_id,
                "approver_authority_digest": receipt_digest(receipt),
                "decision": decision,
                "decided_at": rfc3339(moment - timedelta(seconds=30)),
                "expires_at": rfc3339(moment + timedelta(seconds=artifact_ttl_s)),
            },
            key,
        )
        return {
            "request": request,
            "artifact": artifact,
            "approver_authority_receipt": receipt,
        }
