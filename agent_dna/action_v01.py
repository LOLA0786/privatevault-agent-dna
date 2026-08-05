"""The canonical execution action, and its digest.

One definition, used everywhere. A decision commits to an action by
digesting it; an execution authorization names the same action and
carries the same digest; the dispatch witness attests to bytes derived
from it. If any of those computed the digest slightly differently the
binding would be decorative, so they all call in here.

The action is exactly five fields. Nothing may be added, omitted or
renamed: an unexpected field would change the digest, and a missing one
would let two different actions share it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_dna.authority_v01 import (
    AuthorityFormatError,
    canonicalize,
    sha256_digest,
)

EXECUTION_ACTION_FIELDS = frozenset(
    {
        "subject_principal",
        "subject_key_id",
        "action",
        "resource",
        "parameters",
    }
)

_STRING_FIELDS = (
    "subject_principal",
    "subject_key_id",
    "action",
    "resource",
)


def validate_execution_action(
    action: Any,
    path: str = "action",
) -> Mapping[str, Any]:
    """Strictly validate the five-field canonical action.

    Returns the action unchanged so callers can chain. Raises rather
    than returning a verdict: an action that cannot be validated cannot
    be digested, and there is nothing useful to do with a partial one.
    """
    if not isinstance(action, Mapping):
        raise AuthorityFormatError(f"{path}: expected object")

    present = set(action)
    missing = EXECUTION_ACTION_FIELDS - present
    unexpected = present - EXECUTION_ACTION_FIELDS

    if missing:
        raise AuthorityFormatError(f"{path}: missing field(s) {sorted(missing)}")
    if unexpected:
        raise AuthorityFormatError(f"{path}: unexpected field(s) {sorted(unexpected)}")

    for field in _STRING_FIELDS:
        value = action[field]
        if not isinstance(value, str) or not value:
            raise AuthorityFormatError(f"{path}.{field}: expected non-empty string")

    parameters = action["parameters"]
    if not isinstance(parameters, Mapping):
        raise AuthorityFormatError(f"{path}.parameters: expected object")

    # Surfaces non-canonicalizable values here rather than at digest
    # time, where the failure would be harder to attribute.
    canonicalize(parameters)

    return action


def execution_action_digest(
    action: Any,
    path: str = "action",
) -> str:
    """Digest the validated canonical action.

    Always validates first. A digest over an unvalidated action would
    be a digest over something no verifier will accept.
    """
    return sha256_digest(validate_execution_action(action, path))
