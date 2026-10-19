"""Per-credential API rate limiting (enterprise hardening, DoS)."""

from __future__ import annotations

import importlib

import pytest

from agent_dna.rate_limit import RateLimit, TokenBuckets, rate_limit_from_env


def test_off_by_default():
    assert rate_limit_from_env({}) is None


def test_parse_and_default_burst():
    assert rate_limit_from_env({"PV_RATE_LIMIT_RPS": "5"}) == RateLimit(
        rps=5.0, burst=10
    )
    assert rate_limit_from_env(
        {"PV_RATE_LIMIT_RPS": "0.5", "PV_RATE_LIMIT_BURST": "3"}
    ) == RateLimit(rps=0.5, burst=3)


@pytest.mark.parametrize(
    "env",
    [
        {"PV_RATE_LIMIT_RPS": "x"},
        {"PV_RATE_LIMIT_RPS": "0"},
        {"PV_RATE_LIMIT_RPS": "-1"},
        {"PV_RATE_LIMIT_RPS": "nan"},
        {"PV_RATE_LIMIT_RPS": "inf"},
        {"PV_RATE_LIMIT_RPS": "1", "PV_RATE_LIMIT_BURST": "0"},
        {"PV_RATE_LIMIT_RPS": "1", "PV_RATE_LIMIT_BURST": "1.5"},
    ],
)
def test_invalid_config_refuses(env):
    with pytest.raises(ValueError):
        rate_limit_from_env(env)


def test_token_bucket_refills():
    now = [0.0]
    b = TokenBuckets(RateLimit(rps=1.0, burst=2), clock=lambda: now[0])
    assert b.take("a") == 0.0 and b.take("a") == 0.0
    assert b.take("a") == pytest.approx(1.0)
    assert b.take("b") == 0.0  # other credentials unaffected
    now[0] = 1.0
    assert b.take("a") == 0.0


def test_bucket_memory_bounded():
    b = TokenBuckets(RateLimit(rps=1.0, burst=1, max_keys=3))
    for k in "abcdef":
        b.take(k)
    assert len(b._buckets) == 3


def test_api_returns_429_per_key_and_exempts_probes(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from tests.decide_binding import decide_json

    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "rl.db"))
    monkeypatch.delenv("PV_API_KEYS_FILE", raising=False)
    monkeypatch.setenv("PV_RATE_LIMIT_RPS", "0.001")
    monkeypatch.setenv("PV_RATE_LIMIT_BURST", "2")
    import api.server as server

    importlib.reload(server)
    with TestClient(server.app) as client:
        codes = [
            client.post(
                "/v1/decide",
                json=decide_json("a1", "fs.read"),
                headers={"X-API-Key": "k1"},
            ).status_code
            for _ in range(3)
        ]
        assert codes[:2] != [429, 429] and codes[2] == 429
        r = client.post(
            "/v1/decide", json=decide_json("a1", "fs.read"), headers={"X-API-Key": "k1"}
        )
        assert r.status_code == 429
        assert int(r.headers["retry-after"]) >= 1
        assert r.json()["detail"]["reason_code"] == "RATE_LIMITED"
        other = client.post(
            "/v1/decide", json=decide_json("a1", "fs.read"), headers={"X-API-Key": "k2"}
        )
        assert other.status_code != 429
        assert all(client.get("/ready").status_code != 429 for _ in range(5))
    monkeypatch.delenv("PV_RATE_LIMIT_RPS")
    monkeypatch.delenv("PV_RATE_LIMIT_BURST")
    importlib.reload(server)


def test_server_refuses_to_start_on_bad_rate_limit(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "rl2.db"))
    monkeypatch.delenv("PV_API_KEYS_FILE", raising=False)
    monkeypatch.setenv("PV_RATE_LIMIT_RPS", "fast")
    import api.server as server

    importlib.reload(server)
    with pytest.raises(ValueError, match="PV_RATE_LIMIT_RPS"):
        with TestClient(server.app):
            pass
    monkeypatch.delenv("PV_RATE_LIMIT_RPS")
    importlib.reload(server)
