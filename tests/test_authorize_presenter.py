"""/v1/authorize binds a pinned presenter (ADR 0022).

With PV_PRESENTER_BUNDLE set, every permit names the TLS client key that may
present it, chosen from the operator's pins for the authenticated agent; a
caller cannot name an arbitrary key. Without it, permits stay spec 0.1 and a
requested presenter is refused rather than silently dropped.
"""

from __future__ import annotations

import importlib
import json

import pytest

from agent_dna.authorize_binding import (
    AUTHORIZE_PRESENTER_NOT_PINNED,
    AUTHORIZE_PRESENTER_REQUIRED,
    AUTHORIZE_PRESENTER_UNCONFIGURED,
)
from agent_dna.execution_v01 import (
    EXECUTION_AUTHORIZATION_SPEC,
    EXECUTION_AUTHORIZATION_SPEC_V02,
    validate_execution_authorization,
)
from tests.test_grant_revocation import _decide
from tests.test_wire_action_binding import ORG, _authorize, env  # noqa: F401

PINNED = "sha256:" + "a" * 64
ROTATED = "sha256:" + "b" * 64
STRANGER = "sha256:" + "c" * 64


def _with_presenter(client, key, record, presenter):
    original = client.post

    def post(url, **kw):
        if url == "/v1/authorize" and presenter is not None:
            kw["json"] = dict(kw["json"], presenter_identity_digest=presenter)
        return original(url, **kw)

    client.post = post
    try:
        return _authorize(client, key, record)
    finally:
        client.post = original


@pytest.fixture
def pinned(tmp_path, monkeypatch, request):
    from tests.test_wire_action_binding import AGENT

    bundle = tmp_path / "presenters.json"
    bundle.write_text(
        json.dumps(
            {
                "spec": "pv-presenter-bundle/0.1",
                "organisation_id": ORG,
                "presenters": {AGENT: [PINNED, ROTATED], "someone-else": [STRANGER]},
            }
        )
    )
    monkeypatch.setenv("PV_PRESENTER_BUNDLE", str(bundle))
    return request.getfixturevalue("env")  # noqa: F811 -- after the bundle is set


def _code(response):
    return response.json()["detail"]["reason_code"]


def test_pinned_presenter_is_bound_into_a_v02_permit(pinned):
    record = _decide(pinned["client"], pinned["key"])
    r = _with_presenter(pinned["client"], pinned["key"], record, ROTATED)
    assert r.status_code == 200, r.text
    permit = validate_execution_authorization(r.json()["authorization"])
    assert permit["spec"] == EXECUTION_AUTHORIZATION_SPEC_V02
    assert permit["expected_presenter_identity_digest"] == ROTATED
    runtime = pinned["server"].state["runtime"].composition
    assert runtime["presenter_binding"]["status"] == "attached"


def test_a_permit_must_name_a_presenter(pinned):
    record = _decide(pinned["client"], pinned["key"])
    r = _with_presenter(pinned["client"], pinned["key"], record, None)
    assert r.status_code == 403 and _code(r) == AUTHORIZE_PRESENTER_REQUIRED


def test_another_agents_or_unknown_key_is_refused(pinned):
    record = _decide(pinned["client"], pinned["key"])
    for digest in (STRANGER, "sha256:" + "d" * 64):
        r = _with_presenter(pinned["client"], pinned["key"], record, digest)
        assert r.status_code == 403 and _code(r) == AUTHORIZE_PRESENTER_NOT_PINNED


def test_without_a_bundle_permits_stay_v01_and_a_presenter_is_refused(env):  # noqa: F811
    record = _decide(env["client"], env["key"])
    r = _with_presenter(env["client"], env["key"], record, PINNED)
    assert r.status_code == 422 and _code(r) == AUTHORIZE_PRESENTER_UNCONFIGURED
    plain = _with_presenter(env["client"], env["key"], record, None)
    assert plain.status_code == 200, plain.text
    assert plain.json()["authorization"]["spec"] == EXECUTION_AUTHORIZATION_SPEC


def test_an_unreadable_bundle_stops_startup(tmp_path, monkeypatch):
    bad = tmp_path / "presenters.json"
    bad.write_text('{"spec": "pv-presenter-bundle/0.1"}')
    monkeypatch.setenv("PV_PRESENTER_BUNDLE", str(bad))
    import api.server as server

    importlib.reload(server)
    with pytest.raises(RuntimeError, match="PV_PRESENTER_BUNDLE"):
        server._presenter_bundle()
