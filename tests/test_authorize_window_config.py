"""The authorization window is validated at startup, not parsed per request.

Before this guard, ``/v1/authorize`` read ``PV_AUTHORIZATION_TTL_SECONDS``
with a bare ``int()`` on every call: a non-integer value made every mint a
500, zero or a negative value minted a permit that failed its own schema
(surfacing as a misleading 422), and a huge value silently minted long-lived
permits. The sidecar now judges the window strictly by its own clock
(``SECURITY.md``, fixed issues), so a bounded mint-side ``not_before``
leeway is the one sanctioned place to absorb host clock differences.

Claims -> tests:
  - A malformed, zero, negative, or oversized TTL refuses startup
    -> test_bad_ttl_refuses_startup
  - A malformed or out-of-range not_before leeway refuses startup
    -> test_bad_leeway_refuses_startup
  - An empty value means the default, and the parser's bounds are exact
    -> test_parse_window_defaults_and_bounds
  - A valid TTL is honoured in the minted permit; a leeway moves
    ``not_before`` and ``issued_at`` back without moving ``expires_at``
    -> test_window_values_are_honoured_in_the_minted_permit
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tests.test_authorize_mint_claim import (
    _authorize_body,
    _decide_allow,
    build_mint_env,
)

TTL = "PV_AUTHORIZATION_TTL_SECONDS"
LEEWAY = "PV_AUTHORIZATION_NOT_BEFORE_LEEWAY_SECONDS"


def _ts(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


@pytest.mark.parametrize("value", ["abc", "0", "-5", "301", "1.5", "60s"])
def test_bad_ttl_refuses_startup(tmp_path, monkeypatch, value):
    monkeypatch.setenv(TTL, value)
    env = build_mint_env(tmp_path, monkeypatch)
    with pytest.raises(RuntimeError, match=TTL):
        next(env)


@pytest.mark.parametrize("value", ["abc", "-1", "31"])
def test_bad_leeway_refuses_startup(tmp_path, monkeypatch, value):
    monkeypatch.setenv(LEEWAY, value)
    env = build_mint_env(tmp_path, monkeypatch)
    with pytest.raises(RuntimeError, match=LEEWAY):
        next(env)


def test_parse_window_defaults_and_bounds():
    import api.server as server

    window = server._authorization_window({})
    assert (window.ttl_seconds, window.not_before_leeway_seconds) == (60, 0)
    window = server._authorization_window({TTL: "", LEEWAY: " "})
    assert (window.ttl_seconds, window.not_before_leeway_seconds) == (60, 0)
    window = server._authorization_window({TTL: "1", LEEWAY: "30"})
    assert (window.ttl_seconds, window.not_before_leeway_seconds) == (1, 30)
    window = server._authorization_window({TTL: "300", LEEWAY: "0"})
    assert window.ttl_seconds == 300
    for bad in ({TTL: "0"}, {TTL: "301"}, {LEEWAY: "-1"}, {LEEWAY: "31"}, {TTL: "x"}):
        with pytest.raises(RuntimeError, match="PV_AUTHORIZATION_"):
            server._authorization_window(bad)


def test_window_values_are_honoured_in_the_minted_permit(tmp_path, monkeypatch):
    monkeypatch.setenv(TTL, "120")
    monkeypatch.setenv(LEEWAY, "5")
    # Hold the generator: dropping it would close the TestClient context and
    # run the lifespan shutdown before the requests below.
    gen = build_mint_env(tmp_path, monkeypatch)
    env = next(gen)
    try:
        client, key = env["client"], env["key"]
        record = _decide_allow(client, key)
        response = client.post(
            "/v1/authorize", headers={"X-API-Key": key}, json=_authorize_body(record)
        )
        assert response.status_code == 200, response.text
        body = response.json()
        auth = body["authorization"]
        minted_at = _ts(body["at_time"])
        assert _ts(auth["not_before"]) == minted_at - timedelta(seconds=5)
        assert auth["issued_at"] == auth["not_before"]
        assert _ts(auth["expires_at"]) == minted_at + timedelta(seconds=120)
        # The leeway widens the window backwards only; expires_at is untouched.
        assert _ts(auth["expires_at"]) - _ts(auth["not_before"]) == timedelta(
            seconds=125
        )
    finally:
        gen.close()
