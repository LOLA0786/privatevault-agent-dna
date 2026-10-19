"""A permit never outlives the authority behind its ALLOW.

External review, 19 October 2026, finding 2: an ALLOW could be minted after
the approval or grant that justified it had expired, and a permit could
expire after its approval. The review's four probes are inverted here.

Claims -> tests:
  - Minting after the approval expired is refused, and no permit reaches a
    receiver -> test_mint_after_approval_expiry_is_refused,
    test_secure_profile_refuses_mint_after_approval_expiry
  - A permit expires no later than its approval; the receiver refuses it
    after that -> test_permit_never_outlives_its_approval
  - Minting after the grant expired is refused; a grant ending within the
    permit lifetime caps the permit -> test_mint_after_grant_expiry_is_refused,
    test_permit_is_capped_at_grant_expiry
  - An ALLOW older than PV_DECISION_MINT_WINDOW_SECONDS cannot mint
    -> test_mint_after_decision_window_is_refused
  - Authority that cannot be bounded refuses -> test_unknown_grant_refuses,
    test_approval_without_stored_expiry_refuses, test_deadline_rules
  - The stored approval expiry survives restart and schema migration, on
    SQLite and PostgreSQL -> test_sqlite_*, test_pg_*
  - Concurrent mints near the deadline return one capped permit
    -> test_concurrent_mints_share_one_capped_permit
Legitimate controls: an immediate mint succeeds and the receiver admits it.
"""

from __future__ import annotations

import importlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from nacl.signing import SigningKey

from agent_dna.approval_v01 import approval_artifact_digest
from agent_dna.authority_deadline import (
    APPROVAL_EXPIRY,
    DECISION_WINDOW,
    GRANT_EXPIRY,
    AuthorityUnknownError,
    authority_deadline,
)
from agent_dna.receiver.gate import ReceiverGate
from agent_dna.receiver.ledger import ReceiverLedger
from agent_dna.receiver.permit_header import PERMIT_HEADER, encode_permit_header
from agent_dna.sqlite_store import SQLiteDecisionStore
from tests.pg_support import ADMIN_URL
from tests.test_api_approval_bridge import (  # noqa: F401 - fixture
    PEER,
    WIRE,
    _decide,
    _dispatch,
    _execution_action,
    world,
)
from tests.test_authorize_mint_claim import (  # noqa: F401 - fixture
    AGENT,
    _authorize_body,
    _decide_allow,
    mint_env,
)

EXPIRED = "AUTHORIZE_AUTHORITY_EXPIRED"
# The operation the secure-profile tests declare (ADR 0025).
PAY_INVOICE_OPERATION = {
    "operation_id": "pay-invoice-v1",
    "capability": "payments.pay_invoice",
    "transport": "https",
    "destination": "payments.partner.example",
    "operation": "POST /api/v1/transfers",
    "resource_prefix": "vendor:",
    "parameters_schema": {
        "type": "object",
        "required": ["amount", "currency", "payee_id"],
    },
}
UNKNOWN = "AUTHORIZE_AUTHORITY_UNKNOWN"


def _at(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def freeze_mint_clock(monkeypatch, server, moment: datetime) -> None:
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return moment if tz else moment.replace(tzinfo=None)

    monkeypatch.setattr(server, "_datetime", Clock)


def _mint(env, body):
    return env["client"].post(
        "/v1/authorize", headers={"X-API-Key": env["key"]}, json=body
    )


def _reason(response) -> str:
    return response.json()["detail"]["reason_code"]


def _approved(world_env, *, ttl: int = 30):  # noqa: F811 - fixture name
    approval = world_env["approver"].approve(
        _execution_action(), request_id="req-inv-1", artifact_ttl_s=ttl
    )
    decided = _decide(world_env["client"], world_env["key"], approval)
    assert decided.status_code == 200, decided.text
    record = decided.json()["record"]
    body = _authorize_body(
        record, wire=WIRE, peer=PEER, dispatch=_dispatch(), action=_execution_action()
    )
    body["approval_artifact_digest"] = approval_artifact_digest(approval["artifact"])
    return approval, record, body


def _gate(world_env, tmp_path):  # noqa: F811
    return ReceiverGate(
        receiver_id="payments.partner.example",
        destinations=frozenset({"payments.partner.example"}),
        trust_bundle=json.loads(world_env["bundle_path"].read_text()),
        ledger=ReceiverLedger(tmp_path / "receiver.db"),
        receipt_signing_key=SigningKey.generate(),
        receipt_key_id="independent-receiver",
    )


def _present(gate, auth, *, at):
    return gate.check(
        method="POST",
        path="/api/v1/transfers",
        headers={
            PERMIT_HEADER: encode_permit_header(auth),
            "Content-Type": "application/json",
        },
        body=WIRE,
        received_at=at,
    )


# ---- approval ------------------------------------------------------------------


def test_immediate_mint_is_admitted(world, tmp_path):  # noqa: F811
    _approval, _record, body = _approved(world)
    minted = _mint(world, body)
    assert minted.status_code == 200, minted.text
    auth = minted.json()["authorization"]
    assert _present(_gate(world, tmp_path), auth, at=datetime.now(UTC)).admitted


def test_mint_after_approval_expiry_is_refused(world, monkeypatch):  # noqa: F811
    approval, _record, body = _approved(world)
    later = _at(approval["artifact"]["expires_at"]) + timedelta(days=1)
    freeze_mint_clock(monkeypatch, world["server"], later)
    refused = _mint(world, body)
    assert refused.status_code == 403, refused.text
    assert _reason(refused) == EXPIRED
    assert "approval_expiry" in refused.json()["detail"]["detail"]
    assert "authorization" not in refused.json()


def test_mint_at_the_exact_approval_expiry_is_refused(world, monkeypatch):  # noqa: F811
    approval, _record, body = _approved(world)
    freeze_mint_clock(
        monkeypatch, world["server"], _at(approval["artifact"]["expires_at"])
    )
    assert _reason(_mint(world, body)) == EXPIRED


def test_permit_never_outlives_its_approval(world, tmp_path):  # noqa: F811
    approval, _record, body = _approved(world, ttl=20)  # shorter than the 60 s permit
    minted = _mint(world, body)
    assert minted.status_code == 200, minted.text
    auth = minted.json()["authorization"]
    approval_end = _at(approval["artifact"]["expires_at"])
    assert _at(auth["expires_at"]) <= approval_end
    gate = _gate(world, tmp_path)
    refused = _present(gate, auth, at=approval_end + timedelta(seconds=1))
    assert not refused.admitted  # the receiver enforces the same end


def test_approval_without_stored_expiry_refuses(world):  # noqa: F811
    """A claim recorded before the column existed cannot vouch for a mint."""
    _approval, record, body = _approved(world)
    store = world["server"].state["store"]
    store._conn.execute(
        "UPDATE approval_consume SET not_after = NULL WHERE approval_artifact_digest = ?",
        (record["approval_ref"],),
    )
    store._conn.commit()
    refused = _mint(world, body)
    assert refused.status_code == 403
    assert _reason(refused) == UNKNOWN


def test_secure_profile_refuses_mint_after_approval_expiry(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from tests.approval_world import ApproverWorld
    from tests.decide_binding import decide_json, dispatch_context_for
    from tests.test_authorize_mint_claim import ORG
    from tests.test_init_secure_profile import _load_env
    from tools.init_secure_profile import provision

    out = tmp_path / "secure"
    provision(
        out,
        org=ORG,
        agents=[AGENT],
        grants=[{"agent_id": AGENT, "capability": "payments.pay_invoice"}],
        operations=[PAY_INVOICE_OPERATION],
    )
    grant_path = out / "grants.json"
    rows = json.loads(grant_path.read_text())
    for row in rows:
        if row["agent_id"] == AGENT:
            row["budget"] = 5000
    grant_path.write_text(json.dumps(rows))
    env = _load_env(out / "secure.env", monkeypatch)
    approver = ApproverWorld(ORG)
    approvers = out / "approvers.json"
    approvers.write_text(json.dumps(approver.bundle))
    monkeypatch.setenv("PV_APPROVER_TRUST_BUNDLE", str(approvers))
    import api.server as server

    importlib.reload(server)
    server._pv_signer_cache.clear()
    key = env["PV_KEY_TREASURY_AGENT"]
    approval = approver.approve(
        _execution_action(), request_id="req-inv-1", artifact_ttl_s=30
    )
    with TestClient(server.app) as client:
        assert (
            server.state["runtime"].composition["secure_profile"]["status"]
            == "attached"
        )
        body = decide_json(
            AGENT,
            "payments.pay_invoice",
            arguments=_execution_action()["parameters"],
            resource="vendor:V-100",
            org=ORG,
            dispatch_context=dispatch_context_for(
                adapter="https",
                transport="https",
                operation="POST /api/v1/transfers",
                destination="payments.partner.example",
                wire_content_type="application/json",
            ),
            request_id="req-inv-1",
            execution_id="review-solo-flow",
            approval=approval,
        )
        response = client.post("/v1/decide", headers={"X-API-Key": key}, json=body)
        assert response.status_code == 200, response.text
        record = response.json()["record"]
        assert record["triggered_by"] == "approval"
        freeze_mint_clock(
            monkeypatch,
            server,
            _at(approval["artifact"]["expires_at"]) + timedelta(days=1),
        )
        mint_body = _authorize_body(
            record,
            wire=WIRE,
            peer=PEER,
            dispatch=_dispatch(),
            action=_execution_action(),
        )
        mint_body["approval_artifact_digest"] = approval_artifact_digest(
            approval["artifact"]
        )
        mint_body["security_events"] = [
            {
                "spec": "pv-agent-security-event/1.0",
                "event_id": "review-approval-event",
                "trace_id": "review-solo-flow",
                "occurred_at": approval["artifact"]["decided_at"],
                "source_agent_id": approval["artifact"]["approver_principal"],
                "target_agent_id": AGENT,
                "relation": "APPROVES",
                "action_digest": approval["artifact"]["action_digest"],
                "authorization_id": approval["artifact"]["approval_id"],
                "authorization_state": "VERIFIED",
                "parent_event_id": None,
            }
        ]
        refused = client.post(
            "/v1/authorize", headers={"X-API-Key": key}, json=mint_body
        )
        assert refused.status_code == 403, refused.text
        assert _reason(refused) == EXPIRED


# ---- grants and the decision window ----------------------------------------------


def _grant(env):
    registry = env["server"].state["engine"].authorizer
    return next(g for g in registry._grants.values() if g.agent_id == AGENT)


def test_mint_after_grant_expiry_is_refused(mint_env, monkeypatch):  # noqa: F811
    t0 = datetime.now(UTC)
    _grant(mint_env).expires_at = (t0 + timedelta(seconds=30)).timestamp()
    record = _decide_allow(mint_env["client"], mint_env["key"])
    later = t0 + timedelta(minutes=2)
    import agent_dna.grants as grants

    monkeypatch.setattr(grants, "time", SimpleNamespace(time=lambda: later.timestamp()))
    valid, reason, _ = (
        mint_env["server"].state["engine"].authorizer.explain(AGENT, "crm.read_contact")
    )
    assert not valid and "expired" in reason
    freeze_mint_clock(monkeypatch, mint_env["server"], later)
    refused = _mint(mint_env, _authorize_body(record))
    assert refused.status_code == 403, refused.text
    assert _reason(refused) == EXPIRED
    assert "grant_expiry" in refused.json()["detail"]["detail"]


def test_permit_is_capped_at_grant_expiry(mint_env):  # noqa: F811
    grant_end = (datetime.now(UTC) + timedelta(seconds=20)).replace(microsecond=0)
    _grant(mint_env).expires_at = grant_end.timestamp()
    record = _decide_allow(mint_env["client"], mint_env["key"])
    minted = _mint(mint_env, _authorize_body(record))
    assert minted.status_code == 200, minted.text
    assert _at(minted.json()["authorization"]["expires_at"]) == grant_end


def test_unknown_grant_refuses(mint_env):  # noqa: F811
    """A grant removed from configuration no longer vouches for its ALLOWs."""
    record = _decide_allow(mint_env["client"], mint_env["key"])
    registry = mint_env["server"].state["engine"].authorizer
    del registry._grants[record["approval_ref"]]
    refused = _mint(mint_env, _authorize_body(record))
    assert refused.status_code == 403
    assert _reason(refused) == UNKNOWN


def test_mint_after_decision_window_is_refused(mint_env, monkeypatch):  # noqa: F811
    record = _decide_allow(mint_env["client"], mint_env["key"])
    decided = datetime.fromtimestamp(record["timestamp"], UTC)
    window = mint_env["server"].state["authorization_window"].decision_window_seconds
    assert window == 300  # default
    freeze_mint_clock(
        monkeypatch, mint_env["server"], decided + timedelta(seconds=window - 5)
    )
    assert _mint(mint_env, _authorize_body(record)).status_code == 200
    freeze_mint_clock(
        monkeypatch, mint_env["server"], decided + timedelta(seconds=window + 1)
    )
    refused = _mint(mint_env, _authorize_body(record))
    assert _reason(refused) == EXPIRED
    assert "decision_window" in refused.json()["detail"]["detail"]


def test_decision_window_setting_is_bounded():
    from api.server import _authorization_window

    assert (
        _authorization_window(
            {"PV_DECISION_MINT_WINDOW_SECONDS": "30"}
        ).decision_window_seconds
        == 30
    )
    for bad in ("0", "3601", "soon"):
        with pytest.raises(RuntimeError, match="PV_DECISION_MINT_WINDOW_SECONDS"):
            _authorization_window({"PV_DECISION_MINT_WINDOW_SECONDS": bad})


def test_concurrent_mints_share_one_capped_permit(mint_env):  # noqa: F811
    grant_end = (datetime.now(UTC) + timedelta(seconds=15)).replace(microsecond=0)
    _grant(mint_env).expires_at = grant_end.timestamp()
    record = _decide_allow(mint_env["client"], mint_env["key"])
    body = _authorize_body(record)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _i: _mint(mint_env, body), range(8)))
    assert all(r.status_code == 200 for r in results), [r.text for r in results]
    permits = {json.dumps(r.json()["authorization"], sort_keys=True) for r in results}
    assert len(permits) == 1
    assert _at(results[0].json()["authorization"]["expires_at"]) == grant_end


# ---- the rule itself --------------------------------------------------------------


def _record(**fields):
    base = {
        "timestamp": 1_000_000.0,
        "triggered_by": "authorization",
        "approval_ref": None,
    }
    base.update(fields)
    return base


def _deadline(record, *, approvals=None, grants=None, window=300):
    approvals = approvals or {}
    grants = grants or {}

    def grant_expiry(grant_id):
        return grants[grant_id]  # KeyError for an unknown grant

    return authority_deadline(
        record,
        decision_window_seconds=window,
        approval_not_after=approvals.get,
        grant_expires_at=grant_expiry,
    )


def test_deadline_rules():
    decided = datetime.fromtimestamp(1_000_000.0, UTC)
    plain = _deadline(_record())
    assert (plain.not_after, plain.basis) == (
        decided + timedelta(seconds=300),
        DECISION_WINDOW,
    )

    approved = _deadline(
        _record(triggered_by="approval", approval_ref="sha256:a"),
        approvals={"sha256:a": "1970-01-12T13:47:00Z"},  # 1_000_020
    )
    assert approved.basis == APPROVAL_EXPIRY
    assert approved.not_after == decided + timedelta(seconds=20)

    granted = _deadline(
        _record(approval_ref="grant-1"), grants={"grant-1": 1_000_010.0}
    )
    assert (granted.basis, granted.not_after) == (
        GRANT_EXPIRY,
        decided + timedelta(seconds=10),
    )
    open_grant = _deadline(_record(approval_ref="grant-1"), grants={"grant-1": None})
    assert open_grant.basis == DECISION_WINDOW


@pytest.mark.parametrize(
    "record, approvals, grants",
    [
        (_record(timestamp=None), {}, {}),
        (_record(timestamp=True), {}, {}),
        (_record(triggered_by="approval"), {}, {}),
        (_record(triggered_by="approval", approval_ref="sha256:a"), {}, {}),
        (
            _record(triggered_by="approval", approval_ref="sha256:a"),
            {"sha256:a": "soon"},
            {},
        ),
        (_record(approval_ref="grant-gone"), {}, {}),
    ],
    ids=[
        "no-timestamp",
        "bool-timestamp",
        "approval-no-ref",
        "approval-no-expiry",
        "approval-bad-expiry",
        "unknown-grant",
    ],
)
def test_unbounded_authority_is_refused(record, approvals, grants):
    with pytest.raises(AuthorityUnknownError):
        _deadline(record, approvals=approvals, grants=grants)


# ---- storage --------------------------------------------------------------------


def test_sqlite_stored_expiry_survives_restart(tmp_path):
    path = tmp_path / "pv.db"
    store = SQLiteDecisionStore(path)
    assert store.try_consume_approval(
        "sha256:a",
        organisation_id="org",
        consumed_at="2026-10-19T00:00:00Z",
        not_after="2026-10-19T00:00:30Z",
    )
    store.close()
    assert (
        SQLiteDecisionStore(path).approval_not_after("sha256:a")
        == "2026-10-19T00:00:30Z"
    )
    assert SQLiteDecisionStore(path).approval_not_after("sha256:missing") is None


def test_sqlite_migration_adds_the_column_and_old_claims_stay_unbounded(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE approval_consume (approval_artifact_digest TEXT PRIMARY KEY NOT NULL, "
        "organisation_id TEXT NOT NULL, consumed_at TEXT NOT NULL)"
    )
    conn.execute("INSERT INTO approval_consume VALUES ('sha256:old', 'org', 'then')")
    conn.commit()
    conn.close()
    store = SQLiteDecisionStore(path)
    assert store.approval_not_after("sha256:old") is None  # cannot mint
    assert not store.try_consume_approval(
        "sha256:old", organisation_id="org", consumed_at="now", not_after="later"
    )


pg = pytest.mark.skipif(
    not ADMIN_URL, reason="set TEST_DATABASE_URL to run the PostgreSQL tests"
)


@pg
def test_pg_stored_expiry_and_migration(dsn):
    import psycopg

    with psycopg.connect(
        dsn, autocommit=True
    ) as conn:  # a database from before the column
        conn.execute(
            "CREATE TABLE approval_consume (approval_artifact_digest TEXT PRIMARY KEY, "
            "organisation_id TEXT NOT NULL, consumed_at TEXT NOT NULL)"
        )
        conn.execute(
            "INSERT INTO approval_consume VALUES ('sha256:old', 'org', 'then')"
        )
    from agent_dna.pg_store import PostgresDecisionStore

    store = PostgresDecisionStore(dsn)
    try:
        assert store.approval_not_after("sha256:old") is None
        assert store.try_consume_approval(
            "sha256:a",
            organisation_id="org",
            consumed_at="now",
            not_after="2026-10-19T00:00:30Z",
        )
        assert not store.try_consume_approval(
            "sha256:a", organisation_id="org", consumed_at="now", not_after="x"
        )
    finally:
        store.close()
    reopened = PostgresDecisionStore(dsn)
    try:
        assert reopened.approval_not_after("sha256:a") == "2026-10-19T00:00:30Z"
    finally:
        reopened.close()
