"""The human side of REQUIRE_APPROVAL.

``ApproverKit`` is the approver's own tooling: it holds the approver's keys
and produces the three ``approval_v01`` artifacts the bridge (ADR 0020)
verifies: the immutable request, the signed artifact, and the approver's
authority receipt whose grant chain descends from the organisation's root.
An ``Approver`` decides whether to sign for an exact execution action.

Keys here are generated per run for demos and tests. A deployment pins the
approver bundle with ``PV_APPROVER_TRUST_BUNDLE`` and keeps the private keys
with the humans.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

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


def _rfc3339(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class ApproverKit:
    """One organisation's approver: root authority, approver key, receipt key.

    The root principal is distinct from any approver on purpose: the authority
    verifier refuses a grant chain whose issuer and subject share a principal.
    """

    def __init__(
        self,
        organisation_id: str,
        *,
        principal: str,
        key_id: str,
        root_key: SigningKey | None = None,
        approver_key: SigningKey | None = None,
        receipt_key: SigningKey | None = None,
    ) -> None:
        """Keys default to fresh per-run material. A deployment that keeps
        the approver's keys across processes (a human approving from their
        own terminal) passes the three keys in; the bundle and grant are
        then byte-identical between processes."""
        self.organisation_id = organisation_id
        self.principal = principal
        self.key_id = key_id
        self.root_key = root_key or SigningKey.generate()
        self.approver_key = approver_key or SigningKey.generate()
        self.receipt_key = receipt_key or SigningKey.generate()
        self.bundle: dict[str, Any] = {
            "spec": TRUST_SPEC,
            "canonicalization": CANONICALIZATION,
            "organisation_id": organisation_id,
            "bundle_version": 1,
            "pinned_at": "2026-01-01T00:00:00Z",
            "keys": [
                {
                    "key_id": "authority-root",
                    "principal": f"authority-root@{organisation_id}",
                    "algorithm": "ed25519",
                    "public_key": encode_public_key(self.root_key),
                    "usages": ["root_authority", "grant_issuer"],
                },
                {
                    "key_id": key_id,
                    "principal": principal,
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
        self.grant = sign_grant(
            {
                "spec": GRANT_SPEC,
                "canonicalization": CANONICALIZATION,
                "grant_id": f"g-{key_id}",
                "organisation_id": organisation_id,
                "issuer_principal": f"authority-root@{organisation_id}",
                "issuer_key_id": "authority-root",
                "subject_principal": principal,
                "subject_key_id": key_id,
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
        artifact_ttl_s: int = 300,
    ) -> dict[str, Any]:
        """Sign an approval for exactly ``execution_action``."""
        moment = (now or datetime.now(UTC)).replace(microsecond=0)
        request: dict[str, Any] = {
            "spec": APPROVAL_REQUEST_SPEC,
            "canonicalization": CANONICALIZATION,
            "approval_request_id": f"apr-{uuid.uuid4()}",
            "organisation_id": self.organisation_id,
            "request_id": request_id,
            "created_at": _rfc3339(moment - timedelta(seconds=60)),
            "expires_at": _rfc3339(moment + timedelta(seconds=600)),
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
                "decision_timestamp": _rfc3339(moment - timedelta(seconds=45)),
                "decision_input_digest": request_digest,
                "grant_chain": [self.grant],
                "requested": {
                    "subject_principal": self.principal,
                    "subject_key_id": self.key_id,
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
                "approver_principal": self.principal,
                "approver_key_id": self.key_id,
                "approver_authority_digest": receipt_digest(receipt),
                "decision": "APPROVE",
                "decided_at": _rfc3339(moment - timedelta(seconds=30)),
                "expires_at": _rfc3339(moment + timedelta(seconds=artifact_ttl_s)),
            },
            self.approver_key,
        )
        return {
            "request": request,
            "artifact": artifact,
            "approver_authority_receipt": receipt,
        }


class Approver(Protocol):
    def review(
        self, execution_action: dict[str, Any], *, request_id: str, reason: str
    ) -> dict[str, Any] | None:
        """Return an approval block, or None to decline."""


class ScriptedApprover:
    """Decides with a callable; signs with the kit. Tests and demos."""

    def __init__(
        self,
        kit: ApproverKit,
        decide: Callable[[dict[str, Any], str], bool] = lambda action, reason: True,
    ) -> None:
        self.kit = kit
        self.decide = decide
        self.reviewed: list[tuple[dict[str, Any], str, bool]] = []

    def review(
        self, execution_action: dict[str, Any], *, request_id: str, reason: str
    ) -> dict[str, Any] | None:
        approved = bool(self.decide(execution_action, reason))
        self.reviewed.append((execution_action, reason, approved))
        if not approved:
            return None
        return self.kit.approve(execution_action, request_id=request_id)


class ConsoleApprover:
    """Shows the exact action and asks a human at the terminal."""

    def __init__(self, kit: ApproverKit) -> None:
        self.kit = kit

    def review(
        self, execution_action: dict[str, Any], *, request_id: str, reason: str
    ) -> dict[str, Any] | None:
        print(f"\nAPPROVAL REQUESTED ({reason})")
        print(f"  action    {execution_action['action']}")
        print(f"  resource  {execution_action['resource']}")
        print(f"  params    {execution_action['parameters']}")
        print(f"  digest    {sha256_digest(execution_action)}")
        answer = input("approve exactly this? [y/N] ").strip().lower()
        if answer != "y":
            return None
        return self.kit.approve(execution_action, request_id=request_id)
