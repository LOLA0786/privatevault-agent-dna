"""Grant spend and revocation on PostgreSQL: one budget, one kill switch.

With PV_DATABASE_URL set, every API instance shares the same grant budget
and the same revocations. Runs against a real PostgreSQL when
TEST_DATABASE_URL is set (CI starts one); skipped otherwise.

Covered: concurrent spends from separate instances (separate pools) never
exceed the budget, decimal arithmetic matches the SQLite ledger, budget
refusals leave spend unchanged, revocation is durable and suspends permits
already minted (consume then refuses), the runtime reports Postgres, and
the operator CLI revokes against a postgresql:// URL.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
from decimal import Decimal

import pytest

from agent_dna.connector.adapters.exact_byte_http import _suspension_scopes
from agent_dna.grant_spend import GrantBudgetExceededError, GrantSpendLedger
from tests.pg_support import requires_pg
from tests.test_grant_revocation import _decide
from tests.test_wire_action_binding import ORG, _authorize, env  # noqa: F401

psycopg = pytest.importorskip("psycopg")
pytestmark = requires_pg

from agent_dna.pg_store import (  # noqa: E402
    PostgresDecisionStore,
    PostgresGrantRevocationLedger,
    PostgresGrantSpendLedger,
)


@pytest.fixture
def stores(dsn):
    """Two independent instances: separate pools against one database."""
    a = PostgresDecisionStore(dsn, max_size=16)
    b = PostgresDecisionStore(dsn, max_size=16)
    yield a, b
    a.close()
    b.close()


# ---- spend -----------------------------------------------------------------


def test_two_instances_share_one_budget(stores):
    ledgers = [PostgresGrantSpendLedger(s.pool) for s in stores]
    ok: list[Decimal] = []
    refused: list[str] = []
    lock = threading.Lock()
    barrier = threading.Barrier(20)

    def spend(i):
        barrier.wait()
        try:
            new = ledgers[i % 2].commit_spend("g1", "10", "100")
            with lock:
                ok.append(new)
        except GrantBudgetExceededError as exc:
            with lock:
                refused.append(str(exc))

    threads = [threading.Thread(target=spend, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(ok) == 10 and len(refused) == 10
    assert sorted(ok) == [Decimal(10 * n) for n in range(1, 11)]  # serialised
    assert ledgers[0].spent("g1") == ledgers[1].spent("g1") == Decimal("100")


def test_decimal_arithmetic_matches_sqlite(stores, tmp_path):
    pg = PostgresGrantSpendLedger(stores[0].pool)
    lite = GrantSpendLedger(tmp_path / "pv.db")
    for amount in ("0.1", "0.2", 0.3, "1e-2", 7):
        assert pg.commit_spend("g", amount, None) == lite.commit_spend(
            "g", amount, None
        )
    assert pg.spent("g") == lite.spent("g") == Decimal("7.61")
    assert pg.spent("unknown") == Decimal("0")


def test_refused_spend_leaves_budget_unchanged(stores):
    ledger = PostgresGrantSpendLedger(stores[0].pool)
    ledger.commit_spend("g", "60", "100")
    with pytest.raises(GrantBudgetExceededError):
        ledger.commit_spend("g", "41", "100")
    assert ledger.spent("g") == Decimal("60")
    with pytest.raises(GrantBudgetExceededError):  # a first spend over budget
        ledger.commit_spend("fresh", "101", "100")
    assert ledger.spent("fresh") == Decimal("0")


# ---- revocation ------------------------------------------------------------


def test_revocation_is_shared_and_idempotent(stores):
    one, two = (PostgresGrantRevocationLedger(s.pool) for s in stores)
    assert one.is_revoked("g1") is None and one.is_revoked(None) is None
    first = one.revoke("g1", revoked_by="ops", reason="fraud", store=stores[0])
    again = two.revoke("g1", revoked_by="other", reason="dup", store=stores[1])
    assert first.newly_revoked and not again.newly_revoked
    assert again.revoked_at == first.revoked_at
    seen = two.is_revoked("g1")
    assert seen is not None and seen["revoked_by"] == "ops"
    assert [r["grant_id"] for r in one.revoked()] == ["g1"]
    with pytest.raises(ValueError):
        one.revoke("g2", revoked_by="", reason="x", store=stores[0])


@pytest.fixture
def pg_env(dsn, monkeypatch, request):
    """The API from test_wire_action_binding, on PostgreSQL."""
    monkeypatch.setenv("PV_DATABASE_URL", dsn)
    env = request.getfixturevalue("env")  # noqa: F811 -- after PV_DATABASE_URL is set
    server = env["server"]
    store = server.state["store"]
    assert isinstance(store, PostgresDecisionStore)
    reg = server.state["engine"].authorizer
    ledger = PostgresGrantRevocationLedger(store.pool)
    reg.attach_revocation_ledger(ledger)
    reg.attach_spend_ledger(PostgresGrantSpendLedger(store.pool))
    return env, store, ledger, next(iter(reg._grants))


def test_revocation_suspends_a_minted_permit_on_postgres(pg_env):
    api, store, ledger, grant_id = pg_env
    record = _decide(api["client"], api["key"])
    assert record["approval_ref"] == grant_id
    minted = _authorize(api["client"], api["key"], record)
    assert minted.status_code == 200, minted.text
    permit = minted.json()["authorization"]
    ea_id = permit["execution_authorization_id"]

    result = ledger.revoke(grant_id, revoked_by="ops", reason="fraud", store=store)
    assert result.suspended_authorizations == [ea_id]
    outcome, detail = store.try_consume_unless_suspended(
        ea_id,
        organisation_id=ORG,
        consumed_at="2026-10-17T00:00:00Z",
        scopes=_suspension_scopes(ea_id, ORG, permit),
    )
    assert outcome == "suspended" and grant_id in detail
    assert _authorize(api["client"], api["key"], record).status_code == 403


def test_operator_cli_revokes_on_postgres(stores, dsn):
    base = [sys.executable, "-m", "agent_dna.cli", "grants"]
    out = subprocess.run(
        [
            *base,
            "revoke",
            "g-cli",
            "--db",
            dsn,
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
    seen = PostgresGrantRevocationLedger(stores[0].pool).is_revoked("g-cli")
    assert seen is not None and seen["revoked_by"] == "ops@corp"
    listed = subprocess.run(
        [*base, "revoked", "--db", dsn], capture_output=True, text=True
    )
    assert listed.returncode == 0, listed.stderr
    assert json.loads(listed.stdout)[0]["grant_id"] == "g-cli"


def test_runtime_reports_postgres_spend(dsn, tmp_path, monkeypatch):
    from agent_dna.composition import RuntimeConfig, build_production_runtime

    cap = "payments.transfer"
    monkeypatch.setenv("PV_BASELINE_CAPABILITIES", cap)
    monkeypatch.setenv("PV_DATABASE_URL", dsn)
    grants = [{"agent_id": "a1", "capability": cap, "budget": 100}]
    (tmp_path / "grants.json").write_text(json.dumps(grants))
    cfg = RuntimeConfig.from_env()
    cfg.db_path = str(tmp_path / "pv.db")
    cfg.grants_file = str(tmp_path / "grants.json")
    rt = build_production_runtime(cfg)
    try:
        assert rt.composition["authorization"]["spend"] == "durable (postgresql)"
        assert rt.composition["authorization"]["revocation"] == "durable (postgresql)"
    finally:
        rt.store.close()
