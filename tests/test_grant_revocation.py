"""Revoking a grant has a defined enforcement boundary.

decide -> no longer authorised; mint -> refused (including a revocation that
races the mint); already-minted permits -> suspended, so the dispatcher's
consume refuses them. Revocations are durable.
"""

from __future__ import annotations

import json
import subprocess
import sys

from agent_dna.authorize_binding import AUTHORIZE_GRANT_REVOKED
from agent_dna.connector.adapters.exact_byte_http import _suspension_scopes
from agent_dna.execution_v01 import sha256_bytes_digest
from agent_dna.grant_revocation import GrantRevocationLedger
from tests.decide_binding import decide_json, dispatch_context_for
from tests.test_wire_action_binding import (  # noqa: F401
    AGENT,
    ARGS40,
    CAP,
    ORG,
    WIRE40,
    _authorize,
    env,
)


def _attach(env):  # noqa: F811
    server = env["server"]
    store = server.state["store"]
    reg = server.state["engine"].authorizer
    ledger = GrantRevocationLedger(store.path)
    reg.attach_revocation_ledger(ledger)
    grant_id = next(iter(reg._grants))
    return server, store, ledger, grant_id


def _decide(client, key):
    r = client.post(
        "/v1/decide",
        headers={"X-API-Key": key},
        json=decide_json(
            AGENT,
            CAP,
            arguments=dict(ARGS40),
            resource="erp-sandbox.example",
            org=ORG,
            dispatch_context=dispatch_context_for(
                operation="POST /v1/purchase-orders",
                destination="erp-sandbox.example",
            ),
            expected_wire_bytes_digest=sha256_bytes_digest(WIRE40),
            expected_wire_bytes_length=len(WIRE40),
        ),
    )
    assert r.status_code == 200, r.text
    return r.json()["record"]


def test_decision_records_the_grant_it_used(env):  # noqa: F811
    _, _, _, grant_id = _attach(env)
    record = _decide(env["client"], env["key"])
    assert record["approval_ref"] == grant_id


def test_revoked_grant_no_longer_authorises(env):  # noqa: F811
    _, store, ledger, grant_id = _attach(env)
    ledger.revoke(grant_id, revoked_by="ops", reason="test", store=store)
    r = env["client"].post(
        "/v1/decide",
        headers={"X-API-Key": env["key"]},
        json=decide_json(AGENT, CAP, arguments=dict(ARGS40), org=ORG),
    )
    assert r.json()["decision"] != "allow"
    assert "revoked" in r.json()["reason"]


def test_allow_sealed_before_revocation_cannot_mint(env):  # noqa: F811
    _, store, ledger, grant_id = _attach(env)
    record = _decide(env["client"], env["key"])
    ledger.revoke(grant_id, revoked_by="ops", reason="compromised", store=store)
    r = _authorize(env["client"], env["key"], record)
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["reason_code"] == AUTHORIZE_GRANT_REVOKED


def test_permit_minted_before_revocation_is_suspended_at_consume(env):  # noqa: F811
    _, store, ledger, grant_id = _attach(env)
    record = _decide(env["client"], env["key"])
    minted = _authorize(env["client"], env["key"], record)
    assert minted.status_code == 200, minted.text
    permit = minted.json()["authorization"]
    ea_id = permit["execution_authorization_id"]

    result = ledger.revoke(grant_id, revoked_by="ops", reason="fraud", store=store)
    assert result.suspended_authorizations == [ea_id]

    outcome, detail = store.try_consume_unless_suspended(
        ea_id,
        organisation_id=ORG,
        consumed_at="2026-10-15T00:00:00Z",
        scopes=_suspension_scopes(ea_id, ORG, permit),
    )
    assert outcome == "suspended" and grant_id in detail
    again = _authorize(env["client"], env["key"], record)
    assert again.status_code == 403


def test_revocation_racing_the_mint_suspends_the_new_permit(env, monkeypatch):  # noqa: F811
    _, store, ledger, grant_id = _attach(env)
    record = _decide(env["client"], env["key"])
    real = ledger.is_revoked
    calls = {"n": 0}

    def revoked_after_first_check(gid):
        calls["n"] += 1
        if calls["n"] == 1:
            return None  # pre-mint check passes ...
        if calls["n"] == 2:  # ... revocation commits before the post-check
            ledger.revoke(grant_id, revoked_by="ops", reason="race", store=store)
        return real(gid)

    monkeypatch.setattr(ledger, "is_revoked", revoked_after_first_check)
    r = _authorize(env["client"], env["key"], record)
    assert r.status_code == 403
    assert r.json()["detail"]["reason_code"] == AUTHORIZE_GRANT_REVOKED
    row = store._conn.execute(
        "SELECT execution_authorization_id FROM execution_authorization_mint "
        "WHERE decision_id = ?",
        (record["decision_id"],),
    ).fetchone()
    assert row is not None
    assert store._suspension_in(store._conn, (("authorization", row[0]),))


def test_revocation_is_durable_and_operator_cli_works(env, tmp_path):  # noqa: F811
    _, store, _, grant_id = _attach(env)
    db = str(store.path)
    out = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent_dna.cli",
            "grants",
            "revoke",
            grant_id,
            "--db",
            db,
            "--by",
            "ops@corp",
            "--reason",
            "offboarded",
        ],
        capture_output=True,
        text=True,
    )
    assert out.returncode == 0, out.stderr
    assert "revoked at" in out.stdout
    fresh = GrantRevocationLedger(db)  # a new process / restart view
    assert fresh.is_revoked(grant_id)["revoked_by"] == "ops@corp"
    listed = subprocess.run(
        [sys.executable, "-m", "agent_dna.cli", "grants", "revoked", "--db", db],
        capture_output=True,
        text=True,
    )
    assert json.loads(listed.stdout)[0]["grant_id"] == grant_id
