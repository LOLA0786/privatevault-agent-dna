"""Authority artifacts have a bounded nesting depth (R1 #7).

``_validate_json_value`` and ``canonicalize`` recursed without a depth limit
and ``strict_json_loads`` let ``RecursionError`` escape from the JSON
decoder. Library callers (the receiver gate, verifiers, the CLI) now get an
``AuthorityFormatError`` instead, and the receiver answers a deep permit
header with a 403 refusal receipt rather than a 500.

Claims -> tests:
  - strict_json_loads refuses thousands of nested levels as a format error,
    not a RecursionError
    -> test_strict_json_loads_bounds_depth
  - _validate_json_value and canonicalize refuse depth limit + 1 and accept
    the limit exactly
    -> test_validate_and_canonicalize_bound_depth
  - A permit header carrying deep JSON is RECEIVER_PERMIT_MALFORMED (403)
    with a receipt, not RECEIVER_INTERNAL_ERROR (500)
    -> test_receiver_refuses_deep_permit_header_as_malformed
"""

from __future__ import annotations

import base64

import pytest

from agent_dna.authority_v01 import (
    MAX_JSON_NESTING_DEPTH,
    AuthorityFormatError,
    _validate_json_value,
    canonicalize,
    strict_json_loads,
)
from agent_dna.receiver import gate as g
from agent_dna.receiver.permit_header import PERMIT_HEADER
from tests.receiver._world import METHOD, PARAMETERS, PATH, World, wire_for


def _nested(depth: int):
    value: list = []
    for _ in range(depth - 1):
        value = [value]
    return value


def test_strict_json_loads_bounds_depth():
    deep = "[" * 5000 + "]" * 5000
    with pytest.raises(AuthorityFormatError, match="nesting"):
        strict_json_loads(deep)
    assert strict_json_loads(
        "[" * MAX_JSON_NESTING_DEPTH + "]" * MAX_JSON_NESTING_DEPTH
    )


def test_validate_and_canonicalize_bound_depth():
    _validate_json_value(_nested(MAX_JSON_NESTING_DEPTH))
    canonicalize(_nested(MAX_JSON_NESTING_DEPTH))
    with pytest.raises(AuthorityFormatError, match="nesting"):
        _validate_json_value(_nested(MAX_JSON_NESTING_DEPTH + 1))
    with pytest.raises(AuthorityFormatError, match="nesting"):
        canonicalize(_nested(MAX_JSON_NESTING_DEPTH + 1))
    with pytest.raises(AuthorityFormatError, match="nesting"):
        canonicalize({"a": {"b": _nested(MAX_JSON_NESTING_DEPTH)}})


def test_receiver_refuses_deep_permit_header_as_malformed(tmp_path):
    w = World(tmp_path)
    raw = ("[" * 5000 + "]" * 5000).encode()
    header = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    decision = w.gate.check(
        method=METHOD,
        path=PATH,
        headers={PERMIT_HEADER: header},
        body=wire_for(PARAMETERS),
    )
    assert decision.admitted is False
    assert decision.reason_code == g.RECEIVER_PERMIT_MALFORMED
    assert decision.http_status == 403
    assert decision.receipt is not None
    assert decision.receipt["outcome"] == "REFUSED"
