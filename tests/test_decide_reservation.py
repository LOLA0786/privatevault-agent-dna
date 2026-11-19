"""ADR 0041: the server reserves a business transaction at decide.

Found by audit at 03cd1f6: two decides for one refund, taken before either
was paid, both sealed an ALLOW, because the duplicate rule reads what has
been paid. Each ALLOW minted its own permit.

Claims -> tests:
  - PV_DECIDE_TRANSACTION_KEYS is validated at startup; malformed values
    refuse to start; unset reserves nothing
    -> test_keys_from_env[*], test_malformed_keys_refuse_to_start,
       test_unset_reserves_nothing
  - The key is read from the sealed execution_action.parameters; an
    operation that declares a key and an action without a usable one is a
    finding; the string "7" and the integer 7 are different transactions
    -> test_transaction_key_for
  - One live reservation per key; a lapsed one is taken over; concurrent
    claims grant exactly one; an unsealed hold can be released, a sealed one
    cannot
    -> test_claim_is_exclusive_until_it_lapses,
       test_concurrent_claims_grant_exactly_one,
       test_release_only_drops_an_unsealed_hold
  - Server: the second mintable ALLOW for one transaction is sealed as a
    BLOCK naming the holding decision; a different transaction and an
    undeclared operation are unaffected; a missing key blocks
    -> test_second_allow_for_one_transaction_is_blocked,
       test_other_transactions_and_operations_are_unaffected,
       test_missing_key_blocks
  - Concurrent decides for one transaction seal exactly one ALLOW
    -> test_concurrent_decides_allow_exactly_one
  - After the reservation lapses a new decide is judged on its own; the
    reservation survives a restart
    -> test_lapsed_reservation_allows_a_new_decide,
       test_reservation_survives_restart
  - An audit-only decide (no execution_action) reserves nothing
    -> test_audit_only_decide_does_not_reserve
  - On PostgreSQL the reservation lives in the shared database
    -> test_server_reserves_in_postgres (and, for two replicas,
       tests/test_pg_ledgers.py::test_reservation_has_one_holder_across_instances)
"""

from __future__ import annotations

import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from agent_dna import decide_reservation as dr
from tests.decide_binding import decide_json, dispatch_context_for
from tests.pg_support import requires_pg
from tests.test_authorize_mint_claim import AGENT, ORG, build_mint_env

REFUNDS = "POST /v1/refunds"
KEYS = '{"POST /v1/refunds": "refund_id"}'


# ------------------------------------------------------------------ config


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("", {}),
        ("   ", {}),
        (KEYS, {REFUNDS: "refund_id"}),
        ('{"PUT /v1/x": "body.invoice.id"}', {"PUT /v1/x": "body.invoice.id"}),
    ],
    ids=["unset", "blank", "refund", "dotted"],
)
def test_keys_from_env(raw, expected):
    assert dr.reservation_keys_from_env({dr.RESERVATION_ENV: raw}) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "not json",
        "{}",
        '["POST /v1/refunds"]',
        '{"POST /v1/refunds": 3}',
        '{"GET /v1/refunds": "refund_id"}',
        '{"POST": "refund_id"}',
        '{"POST v1/refunds": "refund_id"}',
        '{"POST /v1/refunds": ""}',
        '{"POST /v1/refunds": "a..b"}',
    ],
    ids=[
        "not-json",
        "empty",
        "list",
        "non-string",
        "read",
        "no-path",
        "relative-path",
        "empty-field",
        "bad-dotted",
    ],
)
def test_malformed_keys_refuse_to_start(raw):
    with pytest.raises(dr.ReservationConfigError):
        dr.reservation_keys_from_env({dr.RESERVATION_ENV: raw})


def _action(parameters):
    return {"parameters": parameters}


def test_transaction_key_for():
    keys = {REFUNDS: "refund_id", "PUT /v1/x": "invoice.id"}
    ctx = {"operation": REFUNDS}
    assert (
        dr.transaction_key_for(keys, _action({"a": 1}), {"operation": "POST /y"})
        is None
    )

    one = dr.transaction_key_for(keys, _action({"refund_id": "RF-1", "amount": 5}), ctx)
    same = dr.transaction_key_for(
        keys, _action({"refund_id": "RF-1", "amount": 50}), ctx
    )
    other = dr.transaction_key_for(keys, _action({"refund_id": "RF-2"}), ctx)
    assert isinstance(one, dr.TransactionKey)
    assert one == same and one != other
    assert one.key_digest.startswith("sha256:")

    as_text = dr.transaction_key_for(keys, _action({"refund_id": "7"}), ctx)
    as_int = dr.transaction_key_for(keys, _action({"refund_id": 7}), ctx)
    assert isinstance(as_text, dr.TransactionKey) and isinstance(
        as_int, dr.TransactionKey
    )
    assert as_text != as_int

    nested = dr.transaction_key_for(
        keys, _action({"invoice": {"id": "INV-9"}}), {"operation": "PUT /v1/x"}
    )
    assert isinstance(nested, dr.TransactionKey)
    # The same value under another operation is another transaction.
    assert (
        nested.key_digest
        != dr.transaction_key_for(
            {REFUNDS: "invoice.id"}, _action({"invoice": {"id": "INV-9"}}), ctx
        ).key_digest
    )

    for bad in (
        {},
        {"refund_id": ""},
        {"refund_id": "  "},
        {"refund_id": None},
        {"refund_id": True},
        {"refund_id": 1.5},
        {"refund_id": ["RF-1"]},
        {"refund_id": {"x": 1}},
    ):
        finding = dr.transaction_key_for(keys, _action(bad), ctx)
        assert isinstance(finding, dr.ReservationFinding), bad
        assert finding.code == dr.TRANSACTION_KEY_MISSING
    assert isinstance(
        dr.transaction_key_for(keys, {"parameters": "x"}, ctx), dr.ReservationFinding
    )


# ------------------------------------------------------------------ ledger


def _key(value: str = "RF-1") -> dr.TransactionKey:
    found = dr.transaction_key_for(
        {REFUNDS: "refund_id"}, _action({"refund_id": value}), {"operation": REFUNDS}
    )
    assert isinstance(found, dr.TransactionKey)
    return found


def test_claim_is_exclusive_until_it_lapses(tmp_path):
    ledger = dr.DecideReservations(tmp_path / "r.db")
    first = ledger.claim(_key(), holder="a", now=1000.0, hold_seconds=300)
    assert first.granted and first.expires_at == 1300.0
    ledger.attach(_key(), holder="a", decision_id="dec-a")

    second = ledger.claim(_key(), holder="b", now=1299.9, hold_seconds=300)
    assert not second.granted
    assert (second.holder, second.decision_id, second.expires_at) == (
        "a",
        "dec-a",
        1300.0,
    )
    # A refused claim changes nothing.
    again = ledger.claim(_key(), holder="c", now=1299.95, hold_seconds=300)
    assert (again.holder, again.expires_at) == ("a", 1300.0)

    assert ledger.claim(_key("RF-2"), holder="b", now=1000.0, hold_seconds=300).granted

    third = ledger.claim(_key(), holder="b", now=1300.0, hold_seconds=300)
    assert third.granted and third.holder == "b" and third.decision_id is None
    with pytest.raises(ValueError):
        ledger.claim(_key(), holder="x", now=1.0, hold_seconds=0)
    ledger.close()

    reopened = dr.DecideReservations(tmp_path / "r.db")
    assert not reopened.claim(_key(), holder="d", now=1400.0, hold_seconds=300).granted
    reopened.close()


def test_concurrent_claims_grant_exactly_one(tmp_path):
    ledger = dr.DecideReservations(tmp_path / "r.db")
    barrier = threading.Barrier(12)

    def claim(i: int) -> bool:
        barrier.wait()
        return ledger.claim(
            _key(), holder=f"h{i}", now=1000.0, hold_seconds=300
        ).granted

    with ThreadPoolExecutor(12) as pool:
        granted = list(pool.map(claim, range(12)))
    assert granted.count(True) == 1


def test_release_only_drops_an_unsealed_hold(tmp_path):
    ledger = dr.DecideReservations(tmp_path / "r.db")
    assert ledger.claim(_key(), holder="a", now=1000.0, hold_seconds=300).granted
    ledger.release(_key(), holder="someone-else")
    assert not ledger.claim(_key(), holder="b", now=1001.0, hold_seconds=300).granted
    ledger.release(_key(), holder="a")
    assert ledger.claim(_key(), holder="b", now=1001.0, hold_seconds=300).granted

    ledger.attach(_key(), holder="b", decision_id="dec-b")
    ledger.release(_key(), holder="b")  # sealed: stays
    assert not ledger.claim(_key(), holder="c", now=1002.0, hold_seconds=300).granted


# ------------------------------------------------------------------ server


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv(dr.RESERVATION_ENV, KEYS)
    yield from build_mint_env(tmp_path, monkeypatch)


def _decide(env, parameters, *, operation=REFUNDS, key="key", **extra):
    return env["client"].post(
        "/v1/decide",
        headers={"X-API-Key": env[key]},
        json=decide_json(
            AGENT,
            "crm.read_contact",
            arguments=dict(parameters),
            resource="crm:contact",
            org=ORG,
            dispatch_context=dispatch_context_for(
                adapter="https",
                transport="https",
                operation=operation,
                destination="crm.store.example",
                wire_content_type="application/json",
            ),
            **extra,
        ),
    )


def test_second_allow_for_one_transaction_is_blocked(env):
    first = _decide(env, {"refund_id": "RF-1", "amount": 1999})
    assert first.status_code == 200, first.text
    holder = first.json()["record"]["decision_id"]

    # Same refund; a different amount is still the same transaction.
    for amount in (1999, 19990):
        second = _decide(env, {"refund_id": "RF-1", "amount": amount})
        assert second.status_code == 403, second.text
        body = second.json()
        assert body["decision"] == "block"
        assert body["triggered_by"] == dr.TRIGGERED_BY_RESERVATION
        assert dr.TRANSACTION_RESERVED in body["reason"] and holder in body["reason"]
        # The refusal is itself a sealed decision record.
        assert body["record"]["decision"] == "block"
        assert body["record"]["decision_id"] != holder
    # Another credential for the same agent is held to the same reservation.
    assert _decide(env, {"refund_id": "RF-1"}, key="other_key").status_code == 403

    manifest = env["server"].state["runtime"].composition["transaction_reservation"]
    assert manifest["enabled"] is True and manifest["operations"] == [REFUNDS]


def test_other_transactions_and_operations_are_unaffected(env):
    assert _decide(env, {"refund_id": "RF-1"}).status_code == 200
    assert _decide(env, {"refund_id": "RF-2"}).status_code == 200
    # No key declared for this operation: nothing is reserved, as before.
    for _ in range(2):
        assert (
            _decide(env, {"refund_id": "RF-1"}, operation="POST /v1/notes").status_code
            == 200
        )


def test_missing_key_blocks(env):
    response = _decide(env, {"amount": 1999})
    assert response.status_code == 403
    assert dr.TRANSACTION_KEY_MISSING in response.json()["reason"]
    # A blocked decide holds nothing.
    assert _decide(env, {"refund_id": "RF-1"}).status_code == 200


def test_concurrent_decides_allow_exactly_one(env):
    """Eight decides for one refund at once: exactly one ALLOW is sealed and
    the other seven are refused by the reservation. (These used to be able to
    fail with an HTTP 500 on SQLite: concurrent decides for one agent raced
    for the chain head. The recorder now serializes them per agent.)"""
    barrier = threading.Barrier(8)

    def go(_: int) -> int:
        barrier.wait()
        return _decide(env, {"refund_id": "RF-RACE", "amount": 1999}).status_code

    with ThreadPoolExecutor(8) as pool:
        codes = list(pool.map(go, range(8)))
    assert codes.count(200) == 1 and codes.count(403) == 7, codes


def test_lapsed_reservation_allows_a_new_decide(env):
    assert _decide(env, {"refund_id": "RF-1"}).status_code == 200
    assert _decide(env, {"refund_id": "RF-1"}).status_code == 403
    # Hold = decision window + margin from the decide.
    conn = sqlite3.connect(env["db_path"])
    reserved_at, expires_at = conn.execute(
        "SELECT reserved_at, expires_at FROM decide_reservations"
    ).fetchone()
    window = env["server"].state["authorization_window"].decision_window_seconds
    assert expires_at - reserved_at == window + dr.CLOCK_MARGIN_SECONDS
    assert abs(reserved_at - time.time()) < 30
    # Lapse it.
    conn.execute("UPDATE decide_reservations SET expires_at = ?", (time.time() - 1,))
    conn.commit()
    conn.close()
    again = _decide(env, {"refund_id": "RF-1"})
    assert again.status_code == 200, again.text
    assert _decide(env, {"refund_id": "RF-1"}).status_code == 403


def test_audit_only_decide_does_not_reserve(env):
    body = {
        "agent_id": AGENT,
        "capability": "crm.read_contact",
        "timestamp": time.time(),
        "arguments": {"refund_id": "RF-1"},
    }
    for _ in range(2):
        r = env["client"].post(
            "/v1/decide", headers={"X-API-Key": env["key"]}, json=body
        )
        assert r.status_code == 200, r.text
    conn = sqlite3.connect(env["db_path"])
    assert conn.execute("SELECT COUNT(*) FROM decide_reservations").fetchone()[0] == 0
    conn.close()
    assert _decide(env, {"refund_id": "RF-1"}).status_code == 200


def test_reservation_survives_restart(tmp_path, monkeypatch):
    monkeypatch.setenv(dr.RESERVATION_ENV, KEYS)
    first = build_mint_env(tmp_path, monkeypatch)
    env = next(first)
    assert _decide(env, {"refund_id": "RF-1"}).status_code == 200
    db_path = env["db_path"]
    first.close()

    conn = sqlite3.connect(db_path)
    assert conn.execute("SELECT COUNT(*) FROM decide_reservations").fetchone()[0] == 1
    conn.close()


def test_unset_reserves_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv(dr.RESERVATION_ENV, raising=False)
    for env in build_mint_env(tmp_path, monkeypatch):
        for _ in range(2):
            assert _decide(env, {"refund_id": "RF-1"}).status_code == 200
        manifest = env["server"].state["runtime"].composition["transaction_reservation"]
        assert manifest["enabled"] is False
        assert env["server"].state["reservations"] is None


def test_malformed_server_config_refuses_to_start(tmp_path, monkeypatch):
    monkeypatch.setenv(dr.RESERVATION_ENV, '{"GET /v1/refunds": "refund_id"}')
    with pytest.raises(dr.ReservationConfigError):
        next(build_mint_env(tmp_path, monkeypatch))


@requires_pg
def test_server_reserves_in_postgres(dsn, tmp_path, monkeypatch):
    psycopg = pytest.importorskip("psycopg")
    monkeypatch.setenv("PV_DATABASE_URL", dsn)
    monkeypatch.setenv(dr.RESERVATION_ENV, KEYS)
    for env in build_mint_env(tmp_path, monkeypatch):
        first = _decide(env, {"refund_id": "RF-PG", "amount": 1999})
        assert first.status_code == 200, first.text
        second = _decide(env, {"refund_id": "RF-PG", "amount": 1999})
        assert second.status_code == 403
        assert first.json()["record"]["decision_id"] in second.json()["reason"]
        assert isinstance(
            env["server"].state["reservations"]._pg, dr.PgCompatConnection
        )
    with psycopg.connect(dsn) as conn:
        rows = conn.execute("SELECT decision_id FROM decide_reservations").fetchall()
    assert rows == [(first.json()["record"]["decision_id"],)]
