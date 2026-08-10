"""Bind POST /v1/authorize minting to a sealed ALLOW DecisionRecord.

No configuration flag disables this binding. Mint without a verifiable
sealed DRP 0.2 ALLOW (action + dispatch-context digests) is refused.
DRP 0.1 records are categorically non-authorizing.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from agent_dna.action_v01 import execution_action_digest
from agent_dna.authority_v01 import AuthorityFormatError
from agent_dna.decision_record import DRP_V02
from agent_dna.dispatch_context_v01 import (
    dispatch_context_digest,
    dispatch_context_from_ea_dispatch,
)

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
AUTHORIZE_ACTION_DIGEST_REQUIRED = "AUTHORIZE_ACTION_DIGEST_REQUIRED"
AUTHORIZE_DISPATCH_CONTEXT_DIGEST_MISMATCH = (
    "AUTHORIZE_DISPATCH_CONTEXT_DIGEST_MISMATCH"
)
AUTHORIZE_DISPATCH_CONTEXT_DIGEST_REQUIRED = (
    "AUTHORIZE_DISPATCH_CONTEXT_DIGEST_REQUIRED"
)
AUTHORIZE_PROTOCOL_NOT_AUTHORIZING = "AUTHORIZE_PROTOCOL_NOT_AUTHORIZING"

EXECUTION_AUTHORIZATION_CONSUMED = "EXECUTION_AUTHORIZATION_CONSUMED"


def normalize_sha256_digest(value: str) -> str:
    """Normalize bare hex or sha256:-prefixed digests to sha256:<hex>."""
    text = value.strip().lower()
    if text.startswith("sha256:"):
        return text
    return f"sha256:{text}"


def _digests_equal(left: str, right: str) -> bool:
    """Constant-time compare for security-sensitive digest equality."""
    a = normalize_sha256_digest(left).encode("utf-8")
    b = normalize_sha256_digest(right).encode("utf-8")
    if len(a) != len(b):
        return False
    return hmac.compare_digest(a, b)


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

    if not _digests_equal(decision_receipt_digest, sealed_hash):
        return AUTHORIZE_RECEIPT_DIGEST_MISMATCH

    if record_hash is not None and not _digests_equal(record_hash, sealed_hash):
        return AUTHORIZE_RECORD_HASH_MISMATCH
    return None


def _protocol_authorizing(record: dict[str, Any]) -> str | None:
    protocol = record.get("protocol_version")
    if protocol != DRP_V02:
        return AUTHORIZE_PROTOCOL_NOT_AUTHORIZING
    return None


def _arguments_binding_reason(
    record: dict[str, Any],
    action: dict[str, Any],
) -> str | None:
    sealed_args = record.get("arguments_digest")
    if not isinstance(sealed_args, str) or not sealed_args:
        return AUTHORIZE_ARGUMENTS_DIGEST_MISMATCH
    observed_args = arguments_digest(arguments_from_action(action))
    # arguments_digest is bare hex in DRP; compare as utf-8 of equal length.
    if not hmac.compare_digest(
        observed_args.encode("utf-8"),
        sealed_args.encode("utf-8"),
    ):
        return AUTHORIZE_ARGUMENTS_DIGEST_MISMATCH
    return None


def _action_digest_binding_reason(
    record: dict[str, Any],
    action: dict[str, Any],
) -> str | None:
    sealed_action_digest = record.get("action_digest")
    if not isinstance(sealed_action_digest, str) or not sealed_action_digest:
        return AUTHORIZE_ACTION_DIGEST_REQUIRED
    try:
        observed_action = execution_action_digest(action)
    except (AuthorityFormatError, TypeError, ValueError):
        return AUTHORIZE_ACTION_DIGEST_MISMATCH
    if not _digests_equal(observed_action, sealed_action_digest):
        return AUTHORIZE_ACTION_DIGEST_MISMATCH
    return None


def _dispatch_digest_binding_reason(
    record: dict[str, Any],
    dispatch: dict[str, Any],
) -> str | None:
    sealed_dispatch = record.get("dispatch_context_digest")
    if not isinstance(sealed_dispatch, str) or not sealed_dispatch:
        return AUTHORIZE_DISPATCH_CONTEXT_DIGEST_REQUIRED
    try:
        context = dispatch_context_from_ea_dispatch(dispatch)
        observed_dispatch = dispatch_context_digest(context)
    except (AuthorityFormatError, TypeError, ValueError):
        return AUTHORIZE_DISPATCH_CONTEXT_DIGEST_MISMATCH
    if not _digests_equal(observed_dispatch, sealed_dispatch):
        return AUTHORIZE_DISPATCH_CONTEXT_DIGEST_MISMATCH
    return None


def _action_binding_reason(
    record: dict[str, Any],
    action: dict[str, Any],
    dispatch: dict[str, Any],
) -> str | None:
    protocol_reason = _protocol_authorizing(record)
    if protocol_reason is not None:
        return protocol_reason

    claimed_capability = capability_from_action(action)
    if claimed_capability is None or claimed_capability != record.get("capability"):
        return AUTHORIZE_ACTION_MISMATCH

    for reason in (
        _arguments_binding_reason(record, action),
        _action_digest_binding_reason(record, action),
        _dispatch_digest_binding_reason(record, dispatch),
    ):
        if reason is not None:
            return reason
    return None


def bind_authorize_to_sealed_allow(
    record: dict[str, Any] | None,
    *,
    agent_id: str,
    decision_receipt_digest: str,
    action: dict[str, Any],
    dispatch: dict[str, Any],
    record_hash: str | None = None,
) -> str | None:
    """Return a reason_code on refusal, or None when mint may proceed.

    Organisation is not a DecisionRecord field; callers must continue to
    bind organisation_id to the trust bundle separately. Wire/peer byte
    digests are not sealed at decide time (Phase 1 / D1).
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

    return _action_binding_reason(record, action, dispatch)
