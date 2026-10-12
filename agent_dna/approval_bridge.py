"""Approval bridge (ADR 0020): a verified, single-use human approval turns
REQUIRE_APPROVAL into ALLOW for exactly one action.

The engine's policy and authorization levels say "this needs a human". Until
this module there was no way to carry a human's answer back into a decision:
``/v1/authorize`` could bind a permit to an ``approval_artifact_digest`` but
nothing checked it, and the only in-tree bridge was a throwaway grant on an
in-process engine.

``ApprovalBridge.consider`` accepts the three ``approval_v01`` artifacts
(immutable request, signed artifact, approver authority receipt) and admits
them only if every one of these holds:

1. the artifact verifies against the operator-pinned approver trust bundle
   (signature, key usage, approver authority receipt, validity windows,
   decision APPROVE) via ``verify_approval_for_execution``, unchanged;
2. the approval binds the exact execution action of this decision (same
   ``action_digest``) and the same organisation;
3. the approval names this agent as the subject;
4. separation of duties: the approver is not the requesting agent and not
   the authenticated caller;
5. the artifact has not been used before (durable single-use claim, the
   same construction as permits).

Anything else leaves the verdict exactly as it was. An approval never
overrides BLOCK and is never consumed by a decision that was already ALLOW.
The bridge judges validity by its own clock, never by anything the caller
sends (the same rule as the sidecar, see SECURITY.md).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from agent_dna.approval_v01 import (
    approval_artifact_digest,
    validate_approval_artifact,
    validate_approval_request,
    verify_approval_for_execution,
)
from agent_dna.authority_v01 import AuthorityFormatError, validate_trust_bundle

APPROVAL_BLOCK_FIELDS = frozenset({"request", "artifact", "approver_authority_receipt"})

APPROVAL_NOT_CONFIGURED = "APPROVAL_NOT_CONFIGURED"
APPROVAL_MALFORMED = "APPROVAL_MALFORMED"
APPROVAL_REQUIRES_BOUND_DECISION = "APPROVAL_REQUIRES_BOUND_DECISION"
APPROVAL_INVALID = "APPROVAL_INVALID"
APPROVAL_ORGANISATION_MISMATCH = "APPROVAL_ORGANISATION_MISMATCH"
APPROVAL_ACTION_MISMATCH = "APPROVAL_ACTION_MISMATCH"
APPROVAL_SUBJECT_MISMATCH = "APPROVAL_SUBJECT_MISMATCH"
APPROVAL_SEPARATION_OF_DUTIES = "APPROVAL_SEPARATION_OF_DUTIES"
APPROVAL_ALREADY_USED = "APPROVAL_ALREADY_USED"
APPROVAL_LEDGER_UNAVAILABLE = "APPROVAL_LEDGER_UNAVAILABLE"

TRIGGERED_BY_APPROVAL = "approval"
# Only these verdict sources may be satisfied by a human approval.
APPROVABLE_TRIGGERS = frozenset({"policy", "authorization"})


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _rfc3339(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class ApprovalContext:
    """What the caller knows about the decision an approval is offered for.

    ``expected_action_digest`` is the digest of the execution action being
    decided (None for an audit-only decide, which cannot use an approval).
    ``requester_identities`` are every identity string the request runs
    under: the agent id, its principal, and the authenticated caller.
    """

    expected_action_digest: str | None
    requester_identities: frozenset[str]


@dataclass(frozen=True)
class ApprovalVerdict:
    ok: bool
    reason_code: str
    detail: str
    artifact_digest: str | None = None
    approver_principal: str | None = None

    @property
    def refusal(self) -> str:
        return f"approval refused: {self.reason_code}: {self.detail}"


class ApprovalBridge:
    """Operator-owned: the approver trust bundle and the single-use ledger."""

    def __init__(
        self,
        *,
        trust_bundle: Mapping[str, Any],
        ledger: Any,
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        keys = validate_trust_bundle(trust_bundle)
        if not any("approval_signer" in key["usages"] for key in keys.values()):
            raise ValueError("approver trust bundle has no approval_signer key")
        if not hasattr(ledger, "try_consume_approval"):
            raise ValueError("approval ledger must implement try_consume_approval")
        self.trust_bundle = trust_bundle
        self.ledger = ledger
        self.clock = clock

    @property
    def organisation_id(self) -> str:
        return str(self.trust_bundle["organisation_id"])

    def consider(
        self,
        approval: Any,
        *,
        context: ApprovalContext,
        agent_id: str,
    ) -> ApprovalVerdict:
        """Evaluate one approval for one decision. Never raises."""
        try:
            return self._consider(approval, context=context, agent_id=agent_id)
        except Exception as exc:  # fail closed on anything unexpected
            return ApprovalVerdict(
                False, APPROVAL_INVALID, f"{type(exc).__name__}: {exc}"
            )

    def _consider(  # noqa: C901 - ordered checklist, each step refuses
        self, approval: Any, *, context: ApprovalContext, agent_id: str
    ) -> ApprovalVerdict:
        if not isinstance(approval, Mapping) or set(approval) != APPROVAL_BLOCK_FIELDS:
            return ApprovalVerdict(
                False,
                APPROVAL_MALFORMED,
                "approval must carry exactly request, artifact and "
                "approver_authority_receipt",
            )
        if context.expected_action_digest is None:
            return ApprovalVerdict(
                False,
                APPROVAL_REQUIRES_BOUND_DECISION,
                "an approval can only satisfy a decision bound to an execution action",
            )
        try:
            request = validate_approval_request(approval["request"])
            artifact = validate_approval_artifact(approval["artifact"])
        except AuthorityFormatError as exc:
            return ApprovalVerdict(False, APPROVAL_MALFORMED, str(exc))

        now = self.clock()
        report = verify_approval_for_execution(
            request,
            artifact,
            self.trust_bundle,
            approval["approver_authority_receipt"],
            at_time=_rfc3339(now),
        )
        if not report.ok:
            return ApprovalVerdict(
                False,
                APPROVAL_INVALID,
                f"{report.reason_code}: " + "; ".join(report.failures),
            )
        if request["organisation_id"] != self.organisation_id:
            return ApprovalVerdict(
                False,
                APPROVAL_ORGANISATION_MISMATCH,
                "approval organisation differs from the pinned approver bundle",
            )
        if request["action_digest"] != context.expected_action_digest:
            return ApprovalVerdict(
                False,
                APPROVAL_ACTION_MISMATCH,
                "approval binds a different action than the one being decided",
            )
        subject = request["action"]
        if subject["subject_key_id"] != agent_id:
            return ApprovalVerdict(
                False,
                APPROVAL_SUBJECT_MISMATCH,
                "approval names a different agent as the subject",
            )
        approver_principal = str(artifact["approver_principal"])
        approver_key_id = str(artifact["approver_key_id"])
        requesters = set(context.requester_identities) | {
            str(subject["subject_principal"]),
            str(subject["subject_key_id"]),
        }
        if approver_principal in requesters or approver_key_id in requesters:
            return ApprovalVerdict(
                False,
                APPROVAL_SEPARATION_OF_DUTIES,
                "the approver is the requesting agent or caller",
            )
        digest = approval_artifact_digest(artifact)
        try:
            claimed = self.ledger.try_consume_approval(
                digest,
                organisation_id=self.organisation_id,
                consumed_at=_rfc3339(now),
            )
        except Exception as exc:
            return ApprovalVerdict(
                False,
                APPROVAL_LEDGER_UNAVAILABLE,
                f"durable claim failed: {type(exc).__name__}",
            )
        if not claimed:
            return ApprovalVerdict(
                False, APPROVAL_ALREADY_USED, "this approval has already been used"
            )
        return ApprovalVerdict(
            True,
            "APPROVED",
            f"approved by {approver_principal}",
            artifact_digest=digest,
            approver_principal=approver_principal,
        )
