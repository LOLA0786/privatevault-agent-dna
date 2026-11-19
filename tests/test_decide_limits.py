"""ADR 0043: per-key daily limits, counted on the server at decide.

Found by probing the live refund demo: five refunds for one customer fired
at once each read "0 refunds today" and all were allowed (Rs 99,995 against
a limit of three).

Claims -> tests:
  - PV_DECIDE_LIMITS is validated; malformed values refuse to start; unset
    counts nothing -> test_config[*], test_bad_config_refuses[*],
    test_server_unset_counts_nothing
  - The key and amount come from the sealed action; the day is the calendar
    day at the configured offset -> test_subject
  - Claims are atomic: the count limit holds under concurrency; the amount
    limit refuses unless the ALLOW was approved, and an approval never lifts
    the count; a release gives a claim back
    -> test_ledger_limits, test_ledger_concurrent_claims
  - Server: concurrent and sequential decides for one customer allow exactly
    max_count; the amount limit blocks; other customers are unaffected
    -> test_server_count_limit_holds, test_server_amount_limit
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

import pytest

from agent_dna import decide_limits as dl
from tests.test_authorize_mint_claim import build_mint_env
from tests.test_decide_reservation import _decide

OP = "POST /v1/refunds"
CFG = '{"POST /v1/refunds": {"key": "customer_id", "max_count": 3, "max_amount": 60000, "utc_offset_minutes": 330}}'


@pytest.mark.parametrize(
    "raw, count, amount, offset",
    [
        (CFG, 3, 60000.0, 330),
        ('{"PUT /x": {"key": "a.b", "max_count": 1}}', 1, None, 0),
    ],
)
def test_config(raw, count, amount, offset):
    [limit] = dl.limits_from_env({dl.LIMITS_ENV: raw}).values()
    assert (limit.max_count, limit.max_amount, limit.utc_offset_minutes) == (
        count,
        amount,
        offset,
    )
    assert dl.limits_from_env({}) == {}


@pytest.mark.parametrize(
    "raw",
    [
        "nope",
        "{}",
        '{"GET /x": {"key": "a", "max_count": 1}}',
        '{"POST /x": {"key": "a"}}',
        '{"POST /x": {"key": "a", "max_count": 0}}',
        '{"POST /x": {"key": "a", "max_amount": -5}}',
        '{"POST /x": {"key": "a", "max_count": 1, "utc_offset_minutes": 900}}',
        '{"POST /x": {"key": "a..b", "max_count": 1}}',
        '{"POST /x": {"key": "a", "max_count": 1, "extra": 1}}',
    ],
)
def test_bad_config_refuses(raw):
    with pytest.raises(dl.LimitConfigError):
        dl.limits_from_env({dl.LIMITS_ENV: raw})


def _limit(**kw):
    return dl.Limit(
        **{
            "operation": OP,
            "key": "customer_id",
            "max_count": 3,
            "max_amount": 60000.0,
            "utc_offset_minutes": 330,
            **kw,
        }
    )


def _subject(
    customer="C-1", amount=19999, when=datetime(2026, 11, 19, 12, tzinfo=UTC), **kw
):
    s = dl.subject_for(
        _limit(**kw), {"parameters": {"customer_id": customer, "amount": amount}}, when
    )
    assert isinstance(s, dl.Subject), s
    return s


def test_subject():
    assert _subject().day == "2026-11-19" and _subject().amount == 1999900
    # 20:00 UTC is 01:30 the next day in India
    assert _subject(when=datetime(2026, 11, 19, 20, tzinfo=UTC)).day == "2026-11-20"
    assert _subject(customer="C-1").key_digest != _subject(customer="C-2").key_digest
    for params in (
        {"amount": 5},
        {"customer_id": "", "amount": 5},
        {"customer_id": "C-1"},
        {"customer_id": "C-1", "amount": True},
    ):
        assert isinstance(
            dl.subject_for(_limit(), {"parameters": params}, datetime.now(UTC)), str
        )


def test_ledger_limits(tmp_path):
    ledger = dl.DecideLimits(tmp_path / "l.db")
    claims = [ledger.claim(_subject(amount=19999), approved=False) for _ in range(3)]
    assert all(isinstance(c, dl.Claim) for c in claims)
    refused = ledger.claim(_subject(amount=1), approved=True)
    assert (
        isinstance(refused, dl.Refusal) and refused.code == dl.DAILY_COUNT_LIMIT
    )  # approval never lifts the count
    ledger.release(claims[-1])
    assert ledger.usage(_subject()) == (2, 3999800)

    big = _subject(customer="C-9", amount=45000)
    assert isinstance(ledger.claim(big, approved=True), dl.Claim)
    over = ledger.claim(_subject(customer="C-9", amount=16000), approved=False)
    assert isinstance(over, dl.Refusal) and over.code == dl.DAILY_AMOUNT_LIMIT
    assert "needs a human approval" in over.detail
    assert isinstance(
        ledger.claim(_subject(customer="C-9", amount=15000), approved=False), dl.Claim
    )  # exactly 60,000
    assert isinstance(
        ledger.claim(_subject(customer="C-9", amount=1), approved=True), dl.Claim
    )  # approved past it
    tomorrow = _subject(
        customer="C-9", amount=1, when=datetime(2026, 11, 20, 12, tzinfo=UTC)
    )
    assert isinstance(ledger.claim(tomorrow, approved=False), dl.Claim)


def test_ledger_concurrent_claims(tmp_path):
    ledger = dl.DecideLimits(tmp_path / "l.db")
    barrier = threading.Barrier(12)

    def go(_):
        barrier.wait()
        return isinstance(ledger.claim(_subject(amount=100), approved=False), dl.Claim)

    with ThreadPoolExecutor(12) as pool:
        assert list(pool.map(go, range(12))).count(True) == 3


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv(dl.LIMITS_ENV, CFG)
    monkeypatch.delenv("PV_DECIDE_TRANSACTION_KEYS", raising=False)
    yield from build_mint_env(tmp_path, monkeypatch)


def _refund(env, i, customer="C-2001", amount=19999):
    r = _decide(
        env,
        {"refund_id": f"RF-{customer}-{i}", "customer_id": customer, "amount": amount},
    )
    return r.status_code, r.json()


def test_server_count_limit_holds(env):
    barrier = threading.Barrier(5)

    def go(i):
        barrier.wait()
        return _refund(env, i)[0]

    with ThreadPoolExecutor(5) as pool:
        codes = list(pool.map(go, range(5)))
    assert codes.count(200) == 3 and codes.count(403) == 2, codes
    status, body = _refund(env, 99)
    assert status == 403 and body["triggered_by"] == dl.TRIGGERED_BY_LIMIT
    assert dl.DAILY_COUNT_LIMIT in body["reason"] and "3 of 3" in body["reason"]
    assert _refund(env, 1, customer="C-2002", amount=100)[0] == 200  # another customer
    manifest = env["server"].state["runtime"].composition["decide_limits"]
    assert manifest["enabled"] and manifest["operations"][OP]["max_amount"] == 60000.0


def test_server_amount_limit(env):
    assert (
        _refund(env, 1, amount=45000)[0] == 200
    )  # no policy in this server: an outright ALLOW
    status, body = _refund(env, 2, amount=16000)
    assert status == 403 and dl.DAILY_AMOUNT_LIMIT in body["reason"]
    assert (
        _refund(env, 3, amount=15000)[0] == 200
    )  # exactly 60,000; the blocked one was not counted


def test_server_unset_counts_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv(dl.LIMITS_ENV, raising=False)
    for env in build_mint_env(tmp_path, monkeypatch):
        for i in range(5):
            assert _refund(env, i)[0] == 200
        assert env["server"].state["decide_limits"] is None
