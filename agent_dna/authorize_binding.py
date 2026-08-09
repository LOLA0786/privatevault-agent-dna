"""Bind POST /v1/authorize minting to a sealed ALLOW DecisionRecord.

No configuration flag disables this binding. Mint without a verifiable
sealed ALLOW is refused.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from agent_dna.action_v01 import execution_action_digest
from agent_dna.authority_v01 import AuthorityFormatError

# Distinct reason codes — auditors must distinguish failure modes.
AUTHORIZE_DECISION_REQUIRED = "AUTHORIZE_DECISION_REQUIRED"
AUTHORIZE_DECISION_NOT_FOUND = "AUTHORIZE_DECISION_NOT_FOUND"
AUTHORIZE_DECISION_NOT_ALLOW = "AUTHORIZE_DECISION_NOT_ALLOW"
AUTHORIZE_AGENT_MISMATCH = "AUTHORIZE_AGENT_MISMATCH"
AUTHORIZE_RECEIPT_DIGEST_MISMATCH = "AUTHORIZE_RECEIPT_DIGEST_MISMATCH"
AUTHORIZE_RECORD_HASH_MISMATCH = "AUTHORIZE_RECORD_HASH_MISMATCH"
AUTHORIZE_ACTION_MISMATCH = "AUTHORIZE_ACTION_MISMATCH"
AUTHORIZE_ARGUMENTS_DIGEST_MISMATCH = "AUTHORIZE_ARGUMENTS_DIGEST_MISMATCH"
AUTHORIZE_ACTION_DIGEST_MISMATCH = "AUTHORIZE_ACTION_DIGEST_MISMATCH"

EXECUTION_AUTHORIZATION_CONSUMED = "EXECUTION_AUTHORIZATION_CONSUMED"


def normalize_sha256_digest(value: str) -> str:
    """Normalize bare hex or sha256:-prefixed digests to sha256:<hex>."""
    text = value.strip().lower()
    if text.startswith("sha256:"):
        return text
    return f"sha256:{text}"


def arguments_digest(arguments: dict[str, Any]) -> str:
    """Match DecisionRecord._digest_arguments (bare 64-hex, no prefix)."""
    canonical = json.dumps(
        arguments,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def capability_from_action(action: dict[str, Any]) -> str | None:
    """Capability claim from authorize action object (decide or EA shapes)."""
    for key in ("capability", "action"):
        value = action.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def arguments_from_action(action: dict[str, Any]) -> dict[str, Any]:
    for key in ("arguments", "parameters"):
        value = action.get(key)
        if isinstance(value, dict):
            return value
    return {}


def _receipt_binding_reason(
    record: dict[str, Any],
    *,
    decision_receipt_digest: str,
    record_hash: str | None,
) -> str | None:
    sealed_hash = record.get("record_hash")
    if not isinstance(sealed_hash, str) or not sealed_hash:
        return AUTHORIZE_DECISION_NOT_FOUND

    sealed_receipt = normalize_sha256_digest(sealed_hash)
    if normalize_sha256_digest(decision_receipt_digest) != sealed_receipt:
        return AUTHORIZE_RECEIPT_DIGEST_MISMATCH

    if (
        record_hash is not None
        and normalize_sha256_digest(record_hash) != sealed_receipt
    ):
        return AUTHORIZE_RECORD_HASH_MISMATCH
    return None


def _action_binding_reason(
    record: dict[str, Any],
    action: dict[str, Any],
) -> str | None:
    claimed_capability = capability_from_action(action)
    if claimed_capability is None or claimed_capability != record.get("capability"):
        return AUTHORIZE_ACTION_MISMATCH

    sealed_args = record.get("arguments_digest")
    if not isinstance(sealed_args, str) or not sealed_args:
        return AUTHORIZE_ARGUMENTS_DIGEST_MISMATCH
    if arguments_digest(arguments_from_action(action)) != sealed_args:
        return AUTHORIZE_ARGUMENTS_DIGEST_MISMATCH

    # drp/0.2 seals an exact execution-action digest; recompute, do not trust.
    sealed_action_digest = record.get("action_digest")
    if isinstance(sealed_action_digest, str) and sealed_action_digest:
        try:
            observed = execution_action_digest(action)
        except (AuthorityFormatError, TypeError, ValueError):
            return AUTHORIZE_ACTION_DIGEST_MISMATCH
        if observed != sealed_action_digest:
            return AUTHORIZE_ACTION_DIGEST_MISMATCH
    return None


def bind_authorize_to_sealed_allow(
    record: dict[str, Any] | None,
    *,
    agent_id: str,
    decision_receipt_digest: str,
    action: dict[str, Any],
    record_hash: str | None = None,
) -> str | None:
    """Return a reason_code on refusal, or None when mint may proceed.

    Organisation is not a DecisionRecord field (drp/0.1); callers must
    continue to bind organisation_id to the trust bundle separately.
    Wire/peer digests are not on the sealed decide record; they remain
    bound into the EA for dispatch-time verification.
    """
    if record is None:
        return AUTHORIZE_DECISION_NOT_FOUND

    if record.get("decision") != "allow":
        return AUTHORIZE_DECISION_NOT_ALLOW

    if record.get("agent_id") != agent_id:
        return AUTHORIZE_AGENT_MISMATCH

    receipt_reason = _receipt_binding_reason(
        record,
        decision_receipt_digest=decision_receipt_digest,
        record_hash=record_hash,
    )
    if receipt_reason is not None:
        return receipt_reason

    return _action_binding_reason(record, action)
