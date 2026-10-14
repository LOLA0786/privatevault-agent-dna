"""Receiver gate binds the headers that change how the upstream reads bytes.

Security review 2026-10: the gate checked body bytes and METHOD+path but
ignored Content-Type and method/URL override headers, and normalised the
method case while forwarding it unchanged.
"""

from __future__ import annotations

import pytest

from agent_dna.receiver.gate import (
    RECEIVER_OPERATION_MISMATCH,
    RECEIVER_WIRE_HEADER_MISMATCH,
)
from agent_dna.receiver.permit_header import PERMIT_HEADER, encode_permit_header

from ._world import NOW, PARAMETERS, PATH, World, wire_for


def _check(world: World, method: str, extra: list[tuple[str, str]]):
    permit = world.permit()
    headers = [(PERMIT_HEADER, encode_permit_header(permit)), *extra]
    return world.gate.check(
        method=method,
        path=PATH,
        headers=headers,
        body=wire_for(PARAMETERS),
        received_at=NOW,
    )


def test_bound_content_type_is_admitted(tmp_path):
    d = _check(World(tmp_path), "POST", [("Content-Type", "application/json")])
    assert d.admitted, d.reason_code


def test_content_type_parameters_are_tolerated(tmp_path):
    d = _check(
        World(tmp_path), "POST", [("Content-Type", "application/json; charset=utf-8")]
    )
    assert d.admitted, d.reason_code


@pytest.mark.parametrize(
    "content_type",
    ["application/x-www-form-urlencoded", "text/plain", "multipart/form-data"],
)
def test_other_content_type_is_refused(tmp_path, content_type):
    d = _check(World(tmp_path), "POST", [("Content-Type", content_type)])
    assert not d.admitted
    assert d.reason_code == RECEIVER_WIRE_HEADER_MISMATCH


def test_two_content_types_are_refused(tmp_path):
    d = _check(
        World(tmp_path),
        "POST",
        [("Content-Type", "application/json"), ("Content-Type", "text/plain")],
    )
    assert d.reason_code == RECEIVER_WIRE_HEADER_MISMATCH


@pytest.mark.parametrize(
    "header",
    [
        "X-HTTP-Method-Override",
        "X-HTTP-Method",
        "X-Method-Override",
        "X-Original-URL",
        "X-Rewrite-URL",
    ],
)
def test_override_headers_are_refused(tmp_path, header):
    d = _check(
        World(tmp_path),
        "POST",
        [("Content-Type", "application/json"), (header, "DELETE")],
    )
    assert not d.admitted
    assert d.reason_code == RECEIVER_WIRE_HEADER_MISMATCH


@pytest.mark.parametrize("method", ["post", "PoSt", "Post"])
def test_method_case_is_not_normalised(tmp_path, method):
    d = _check(World(tmp_path), method, [("Content-Type", "application/json")])
    assert not d.admitted
    assert d.reason_code == RECEIVER_OPERATION_MISMATCH


def test_refused_header_attempt_does_not_consume_permit(tmp_path):
    world = World(tmp_path)
    permit = world.permit()
    encoded = encode_permit_header(permit)
    bad = world.gate.check(
        method="POST",
        path=PATH,
        headers=[(PERMIT_HEADER, encoded), ("Content-Type", "text/plain")],
        body=wire_for(PARAMETERS),
        received_at=NOW,
    )
    assert not bad.admitted
    good = world.gate.check(
        method="POST",
        path=PATH,
        headers=[(PERMIT_HEADER, encoded), ("Content-Type", "application/json")],
        body=wire_for(PARAMETERS),
        received_at=NOW,
    )
    assert good.admitted, good.reason_code
