"""The canonical execution action is the binding surface.

A decision commits to an action by digesting it; an authorization names
the same action and carries the same digest. If the two could compute
different digests over the same action, or the same digest over
different actions, the binding would prove nothing. These tests pin both
directions.
"""

import pytest

from agent_dna.action_v01 import (
    EXECUTION_ACTION_FIELDS,
    execution_action_digest,
    validate_execution_action,
)
from agent_dna.authority_v01 import AuthorityFormatError, sha256_digest

VALID = {
    "subject_principal": "service-agent@retail.example",
    "subject_key_id": "service-agent-07",
    "action": "refunds.issue",
    "resource": "account:CUST-88213",
    "parameters": {"amount": 240000, "currency": "USD"},
}


def _without(field):
    return {k: v for k, v in VALID.items() if k != field}


def test_valid_action_validates_and_is_returned_unchanged():
    assert validate_execution_action(dict(VALID)) == VALID


def test_digest_equals_the_underlying_canonical_digest():
    """The helper must not introduce a second canonicalization: a permit
    validated by execution_v01 and a decision sealed by the runtime have
    to agree byte for byte."""
    assert execution_action_digest(dict(VALID)) == sha256_digest(VALID)


def test_key_insertion_order_does_not_change_the_digest():
    reversed_order = dict(reversed(list(VALID.items())))
    assert list(reversed_order) != list(VALID)
    assert execution_action_digest(reversed_order) == execution_action_digest(
        dict(VALID)
    )


@pytest.mark.parametrize("field", sorted(EXECUTION_ACTION_FIELDS))
def test_every_field_is_required(field):
    with pytest.raises(AuthorityFormatError, match="missing field"):
        validate_execution_action(_without(field))


def test_unexpected_field_is_rejected():
    """An extra field would change the digest, so a verifier that
    tolerated it would accept an action it never checked."""
    with pytest.raises(AuthorityFormatError, match="unexpected field"):
        validate_execution_action(dict(VALID, escalate=True))


@pytest.mark.parametrize(
    "field",
    ["subject_principal", "subject_key_id", "action", "resource"],
)
def test_empty_string_fields_are_rejected(field):
    with pytest.raises(AuthorityFormatError, match="non-empty string"):
        validate_execution_action(dict(VALID, **{field: ""}))


@pytest.mark.parametrize("value", [None, 1, "string", ["list"]])
def test_non_mapping_parameters_are_rejected(value):
    with pytest.raises(AuthorityFormatError, match="expected object"):
        validate_execution_action(dict(VALID, parameters=value))


def test_non_object_action_is_rejected():
    with pytest.raises(AuthorityFormatError, match="expected object"):
        validate_execution_action(["not", "an", "action"])


@pytest.mark.parametrize(
    "value",
    [
        float("nan"),
        float("inf"),
        float("-inf"),
        b"bytes",
        {"a", "set"},
    ],
)
def test_non_canonical_parameter_values_are_rejected(value):
    """Rejected at validation, not silently coerced at digest time: a
    coerced value would digest to something no verifier reproduces."""
    with pytest.raises(AuthorityFormatError):
        validate_execution_action(dict(VALID, parameters={"amount": value}))


@pytest.mark.parametrize(
    "mutation",
    [
        {"subject_principal": "attacker@retail.example"},
        {"subject_key_id": "service-agent-99"},
        {"action": "refunds.approve"},
        {"resource": "account:CUST-00001"},
        {"parameters": {"amount": 240001, "currency": "USD"}},
        {"parameters": {"amount": 240000, "currency": "EUR"}},
    ],
)
def test_any_change_changes_the_digest(mutation):
    assert execution_action_digest(dict(VALID, **mutation)) != (
        execution_action_digest(dict(VALID))
    )


def test_digest_validates_before_digesting():
    """A digest over an unvalidated action would be a digest over
    something no verifier will accept."""
    with pytest.raises(AuthorityFormatError):
        execution_action_digest(dict(VALID, extra="field"))
