"""Request size and JSON nesting are bounded before anything parses them (R1 #7).

Before this guard a few thousand nested brackets inside a 1 MB body raised
``RecursionError`` inside JSON parsing on ``/v1/decide`` and ``/v1/authorize``
(a 500, and CPU burned per request), and the app had no body size limit of
its own.

Claims -> tests:
  - 5000-level nesting on /v1/decide and /v1/authorize is a clean 400 with a
    reason code, never a 500 or an unhandled RecursionError
    -> test_deep_nesting_is_refused_on_decide
    -> test_deep_nesting_is_refused_on_authorize
  - A body over PV_MAX_REQUEST_BYTES is 413 before parsing, with or without
    Content-Length
    -> test_oversize_body_is_413
    -> test_oversize_chunked_body_is_413
  - Nesting at the limit still parses (the bound is exact)
    -> test_nesting_at_the_limit_is_accepted
  - Bounds come from the environment and are validated at startup
    -> test_bad_bound_refuses_startup
  - The depth scanner ignores brackets inside strings and escaped quotes
    -> test_depth_scanner
"""

from __future__ import annotations

import importlib

import pytest
from fastapi.testclient import TestClient

from agent_dna.authority_v01 import MAX_JSON_NESTING_DEPTH


def _server(tmp_path, monkeypatch, **env: str):
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "bounds.db"))
    monkeypatch.setenv("PV_ALLOW_NO_AUTH", "1")
    monkeypatch.delenv("PV_API_KEYS_FILE", raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    import api.server as server

    importlib.reload(server)
    return server


def _nested(depth: int) -> str:
    return "[" * depth + "]" * depth


def _decide_body(arguments_json: str) -> bytes:
    return (
        '{"agent_id":"bounds-agent","capability":"crm.read_contact",'
        '"timestamp":1751700000,"arguments":{"a":' + arguments_json + "}}"
    ).encode()


JSON = {"Content-Type": "application/json"}


def test_deep_nesting_is_refused_on_decide(tmp_path, monkeypatch):
    server = _server(tmp_path, monkeypatch)
    with TestClient(server.app) as client:
        r = client.post("/v1/decide", content=_decide_body(_nested(5000)), headers=JSON)
    assert r.status_code == 400, r.text
    assert r.json()["detail"]["reason_code"] == "REQUEST_JSON_TOO_DEEP"


def test_deep_nesting_is_refused_on_authorize(tmp_path, monkeypatch):
    server = _server(tmp_path, monkeypatch)
    body = (
        '{"request_id":"r","agent_id":"a","organisation_id":"o","action":'
        + _nested(5000)
        + "}"
    ).encode()
    with TestClient(server.app) as client:
        r = client.post("/v1/authorize", content=body, headers=JSON)
    assert r.status_code == 400, r.text
    assert r.json()["detail"]["reason_code"] == "REQUEST_JSON_TOO_DEEP"


def test_nesting_at_the_limit_is_accepted(tmp_path, monkeypatch):
    """Exactly MAX_JSON_NESTING_DEPTH levels pass the gate; the request then
    fails or succeeds on its merits, never on the bound."""
    server = _server(tmp_path, monkeypatch)
    # arguments.a already sits at depth 2 inside the body object.
    inner = _nested(MAX_JSON_NESTING_DEPTH - 2)
    with TestClient(server.app) as client:
        r = client.post("/v1/decide", content=_decide_body(inner), headers=JSON)
    assert (
        r.status_code != 400
        or r.json()["detail"].get("reason_code") != "REQUEST_JSON_TOO_DEEP"
    )


def test_oversize_body_is_413(tmp_path, monkeypatch):
    server = _server(tmp_path, monkeypatch, PV_MAX_REQUEST_BYTES="4096")
    body = b'{"pad":"' + b"x" * 8192 + b'"}'
    with TestClient(server.app) as client:
        r = client.post("/v1/decide", content=body, headers=JSON)
    assert r.status_code == 413, r.text
    assert r.json()["detail"]["reason_code"] == "REQUEST_TOO_LARGE"


def test_oversize_chunked_body_is_413(tmp_path, monkeypatch):
    server = _server(tmp_path, monkeypatch, PV_MAX_REQUEST_BYTES="4096")

    def chunks():
        yield b'{"pad":"'
        for _ in range(16):
            yield b"x" * 1024
        yield b'"}'

    with TestClient(server.app) as client:
        r = client.post("/v1/decide", content=chunks(), headers=JSON)
    assert r.status_code == 413, r.text
    assert r.json()["detail"]["reason_code"] == "REQUEST_TOO_LARGE"


@pytest.mark.parametrize("value", ["abc", "0", "512", "-1", "999999999999"])
def test_bad_bound_refuses_startup(tmp_path, monkeypatch, value):
    server = _server(tmp_path, monkeypatch, PV_MAX_REQUEST_BYTES=value)
    with pytest.raises(RuntimeError, match="PV_MAX_REQUEST_BYTES"):
        with TestClient(server.app):
            pass


def test_depth_scanner():
    from agent_dna.request_bounds import json_nesting_depth

    assert json_nesting_depth(b'{"a":"[[[[["}') == 1
    assert json_nesting_depth(b'[[{"a":[]}]]') == 4
    assert json_nesting_depth(b'"\\"[["') == 0
    assert json_nesting_depth(b"") == 0
    assert json_nesting_depth(b"[" * 5000 + b"]" * 5000) == 5000
    # Early exit: the scanner stops as soon as the limit is passed.
    assert json_nesting_depth(b"[" * 5000, limit=10) == 11
