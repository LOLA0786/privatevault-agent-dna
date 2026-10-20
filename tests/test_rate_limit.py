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


def _limited_api(tmp_path, monkeypatch, rps="0.001", burst="2"):
    import json

    from agent_dna.apikeys import generate_key

    keys = {n: generate_key(n, "full") for n in ("a1", "a2")}
    path = tmp_path / "keys.json"
    path.write_text(
        json.dumps(
            {k["hash"]: {"name": k["name"], "scope": "full"} for k in keys.values()}
        )
    )
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "rl.db"))
    monkeypatch.setenv("PV_API_KEYS_FILE", str(path))
    monkeypatch.setenv("PV_RATE_LIMIT_RPS", rps)
    monkeypatch.setenv("PV_RATE_LIMIT_BURST", burst)
    import api.server as server

    importlib.reload(server)
    return server, {n: k["key"] for n, k in keys.items()}


def _decide(client, key, agent="a1"):
    from tests.decide_binding import decide_json

    return client.post(
        "/v1/decide", json=decide_json(agent, "fs.read"), headers={"X-API-Key": key}
    )


def test_api_returns_429_per_key_and_exempts_probes(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    server, keys = _limited_api(tmp_path, monkeypatch)
    with TestClient(server.app) as client:
        codes = [_decide(client, keys["a1"]).status_code for _ in range(3)]
        assert codes[:2] != [429, 429] and codes[2] == 429
        r = _decide(client, keys["a1"])
        assert r.status_code == 429
        assert int(r.headers["retry-after"]) >= 1
        assert r.json()["detail"]["reason_code"] == "RATE_LIMITED"
        # another registered agent has its own budget
        assert _decide(client, keys["a2"], "a2").status_code != 429
        assert all(client.get("/ready").status_code != 429 for _ in range(5))


def test_invented_keys_do_not_get_fresh_buckets(tmp_path, monkeypatch):
    """Review 2026-10-20: keys were bucketed before authentication, so a
    made-up key per request was never limited."""
    import uuid

    from fastapi.testclient import TestClient

    server, _keys = _limited_api(tmp_path, monkeypatch)
    with TestClient(server.app) as client:
        codes = [_decide(client, uuid.uuid4().hex).status_code for _ in range(20)]
        assert codes.count(429) == 18  # burst 2, then the shared address bucket
        assert _decide(client, "").status_code == 429  # no key: same address


def test_junk_traffic_cannot_reset_a_registered_bucket():
    import asyncio
    import uuid

    from agent_dna.rate_limit import RateLimitMiddleware

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    real = "registered-key"
    mw = RateLimitMiddleware(
        app,
        limit=lambda: RateLimit(rps=0.001, burst=1, max_keys=5),
        known=lambda key: key == real,
    )

    async def status(key, addr):
        out = []

        async def send(m):
            out.append(m)

        scope = {
            "type": "http",
            "path": "/v1/decide",
            "headers": [(b"x-api-key", key.encode())],
            "client": (addr, 1),
        }
        await mw(scope, None, send)
        return out[0]["status"]

    async def go():
        assert await status(real, "10.0.0.1") == 200
        assert await status(real, "10.0.0.1") == 429
        for n in range(50):  # junk from many addresses
            await status(uuid.uuid4().hex, f"10.1.0.{n}")
        return await status(real, "10.0.0.1")

    assert asyncio.run(go()) == 429  # still limited: its bucket was not evicted


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
