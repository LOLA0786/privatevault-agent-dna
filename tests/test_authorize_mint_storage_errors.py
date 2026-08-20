"""Authorize mint storage failures use typed HTTP contracts."""

from __future__ import annotations

import sqlite3

import pytest

from tests.test_authorize_mint_claim import (
    _authorize_body,
    _decide_allow,
    build_mint_env,
)


@pytest.fixture
def mint_env(tmp_path, monkeypatch):
    yield from build_mint_env(tmp_path, monkeypatch)


SENSITIVE = ("pv.db", "SQL", "signing_key", "new_seed", "/Users/")


def _detail_blob(response) -> str:
    return json_dumps(response.json())


def json_dumps(value) -> str:
    import json

    return json.dumps(value)


def test_binding_conflict_and_permit_states_keep_existing_codes(mint_env) -> None:
    client, key = mint_env["client"], mint_env["key"]
    record = _decide_allow(client, key)
    body = _authorize_body(record)
    first = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
    assert first.status_code == 200

    def _run(status: str, http: int, reason: str) -> None:
        def _fake(**kwargs):
            return status, None

        mint_env["server"].state["store"].claim_or_replay_mint = _fake
        r = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
        assert r.status_code == http, r.text
        assert r.json()["detail"]["reason_code"] == reason
        assert "authorization" not in r.json()

    _run("conflict", 403, "AUTHORIZE_PERMIT_BINDING_CONFLICT")
    _run("consumed", 409, "AUTHORIZE_PERMIT_ALREADY_CONSUMED")
    _run("expired", 409, "AUTHORIZE_PERMIT_EXPIRED")
    _run("indeterminate", 409, "AUTHORIZE_PERMIT_INDETERMINATE")


def test_sqlite_operational_error_is_503_without_sensitive_detail(mint_env) -> None:
    client, key = mint_env["client"], mint_env["key"]
    record = _decide_allow(client, key)
    body = _authorize_body(record)

    def _locked(**kwargs):
        raise sqlite3.OperationalError(
            "database is locked: /secret/path/privatevault.db SELECT * FROM mint"
        )

    mint_env["server"].state["store"].claim_or_replay_mint = _locked
    r = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
    assert r.status_code == 503, r.text
    blob = _detail_blob(r)
    assert "authorization" not in r.json()
    assert "/secret/path" not in blob
    assert "SELECT" not in blob
    assert "privatevault.db" not in blob
    assert r.json()["detail"]["reason_code"] == "AUTHORIZE_STORE_UNAVAILABLE"


def test_sqlite_database_error_is_503_without_sensitive_detail(mint_env) -> None:
    client, key = mint_env["client"], mint_env["key"]
    record = _decide_allow(client, key)
    body = _authorize_body(record)

    def _corrupt(**kwargs):
        raise sqlite3.DatabaseError("database disk image is malformed at /tmp/keys.db")

    mint_env["server"].state["store"].claim_or_replay_mint = _corrupt
    r = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
    assert r.status_code == 503, r.text
    blob = _detail_blob(r)
    assert "authorization" not in r.json()
    assert "/tmp/keys.db" not in blob
    assert "malformed" not in blob
    assert r.json()["detail"]["reason_code"] == "AUTHORIZE_STORE_UNAVAILABLE"


def test_domain_validation_error_is_4xx_without_authorization(mint_env) -> None:
    client, key = mint_env["client"], mint_env["key"]
    record = _decide_allow(client, key)
    body = _authorize_body(record)

    def _invalid(**kwargs):
        raise ValueError("seed=deadbeef path=/Users/rinky/secret.db")

    mint_env["server"].state["store"].claim_or_replay_mint = _invalid
    r = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
    assert r.status_code == 422, r.text
    blob = _detail_blob(r)
    assert "authorization" not in r.json()
    assert "deadbeef" not in blob
    assert "/Users/rinky" not in blob


def test_unexpected_internal_failure_is_500_without_raw_exception(mint_env) -> None:
    client, key = mint_env["client"], mint_env["key"]
    record = _decide_allow(client, key)
    body = _authorize_body(record)

    def _boom(**kwargs):
        raise RuntimeError("SQL dump /Users/rinky/agentdna/privatevault.db seed=abc")

    mint_env["server"].state["store"].claim_or_replay_mint = _boom
    r = client.post("/v1/authorize", headers={"X-API-Key": key}, json=body)
    assert r.status_code == 500, r.text
    blob = _detail_blob(r)
    assert "authorization" not in r.json()
    assert "SQL dump" not in blob
    assert "/Users/rinky" not in blob
    assert "seed=abc" not in blob
