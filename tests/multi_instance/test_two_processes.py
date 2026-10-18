"""Two real API processes, one PostgreSQL: the guarantees hold across them.

Each test starts two uvicorn processes (separate memory and connection
pools) on a fresh database and sends requests round-robin across them, as a
load balancer would. Then it breaks things: kills a process mid-load and
takes the database away. Runs when TEST_DATABASE_URL is set (CI starts
PostgreSQL 16); skipped otherwise.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal

import httpx
import pytest

from tests.pg_support import ADMIN_URL, requires_pg

psycopg = pytest.importorskip("psycopg")
pytestmark = requires_pg

from tests.multi_instance.cluster import (  # noqa: E402
    APPROVE,
    INITIATE,
    Cluster,
    load,
    verdict_of,
)


@pytest.fixture
def cluster(dsn):
    with Cluster(dsn, instances=2, budget=100) as c:
        yield c


def _sql(dsn: str, query: str, *params: object) -> list[tuple]:
    with psycopg.connect(dsn) as conn:
        return conn.execute(query, params).fetchall()


def _spent(dsn: str) -> Decimal:
    rows = _sql(dsn, "SELECT spent FROM grant_spend WHERE grant_id = 'grant-payer-1'")
    return Decimal(rows[0][0]) if rows else Decimal(0)


def _assert_verified(cluster: Cluster, node=None, agent: str = "payer-1") -> None:
    """Chains verified from the shared store, not a per-process snapshot."""
    report = cluster.get("/v1/verify", node=node)
    assert report["chain_integrity_verified"] is True
    assert report["chains"].get(agent) is True, report["chains"]  # not vacuous


def _decide_many(cluster: Cluster, n: int, amount: int, workers: int = 16) -> list[str]:
    def one(_):
        body, _wire = cluster.payment(amount)
        r = cluster.post("/v1/decide", "payer-1", body)
        return verdict_of(r)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(one, range(n)))


def test_budget_holds_across_processes(cluster, dsn):
    verdicts = _decide_many(cluster, 40, amount=5)
    assert verdicts.count("allow") == 20, verdicts  # 20 x 5 = budget 100
    # The losers are budget refusals: no 5xx, and no BLOCK from a lost race.
    assert set(verdicts) == {"allow", "require_approval"}, verdicts
    assert _spent(dsn) == 100
    _assert_verified(cluster)


def test_one_permit_per_decision_across_processes(cluster, dsn):
    body, wire = cluster.payment(7)
    decided = cluster.post("/v1/decide", "payer-1", body, node=cluster.nodes[0])
    assert decided.status_code == 200 and decided.json()["decision"] == "allow"
    record = decided.json()["record"]
    request = cluster.authorize_body(record, body["arguments"], wire)

    def mint(i):
        return cluster.post(
            "/v1/authorize", "payer-1", request, node=cluster.nodes[i % 2]
        )

    with ThreadPoolExecutor(max_workers=10) as pool:
        responses = list(pool.map(mint, range(10)))
    permits = {
        r.json()["authorization"]["execution_authorization_id"]
        for r in responses
        if r.status_code == 200
    }
    assert len(permits) == 1, [r.text[:200] for r in responses]
    assert all(r.status_code in (200, 409) for r in responses), [
        r.status_code for r in responses
    ]
    rows = _sql(
        dsn,
        "SELECT COUNT(*) FROM execution_authorization_mint WHERE decision_id = %s",
        record["decision_id"],
    )
    assert rows == [(1,)]


def test_self_approval_is_blocked_across_processes(cluster):
    a, b = cluster.nodes
    initiate = cluster.post(
        "/v1/decide", "maker-1", cluster.wire_decide("maker-1", INITIATE), node=a
    )
    assert initiate.status_code == 200, initiate.text
    target = {"approves": initiate.json()["record"]["record_hash"]}

    own = cluster.post(
        "/v1/decide", "maker-1", cluster.wire_decide("maker-1", APPROVE, target), node=b
    )
    assert own.json()["decision"] == "block"
    assert "maker==checker" in own.json()["reason"]

    ok = cluster.post(
        "/v1/decide",
        "checker-1",
        cluster.wire_decide("checker-1", APPROVE, target),
        node=b,
    )
    assert ok.json()["decision"] == "allow", ok.text
    again = cluster.post(
        "/v1/decide",
        "checker-1",
        cluster.wire_decide("checker-1", APPROVE, target),
        node=a,
    )
    assert again.json()["decision"] == "block"
    assert "already been approved" in again.json()["reason"]


def test_killing_an_instance_mid_load_never_overspends(cluster, dsn):
    def kill_soon():
        time.sleep(0.6)
        cluster.kill(1)  # SIGKILL: no graceful shutdown, transactions cut

    killer = threading.Thread(target=kill_soon)
    killer.start()
    report = load(cluster, 300, 16, amount=1)
    killer.join()
    allowed = report["verdicts"].get("allow", 0)
    spent = _spent(dsn)
    assert spent <= 100  # the budget is never exceeded
    assert allowed <= spent  # every allow the client saw was paid for
    recorded = _sql(
        dsn,
        "SELECT COUNT(*) FROM records WHERE kind = 'decision' AND agent_id = 'payer-1' "
        "AND decision = 'allow'",
    )[0][0]
    assert allowed <= recorded <= spent  # an allow is recorded and paid for

    cluster.start(1)  # the restarted process sees the shared state
    remaining = 100 - int(_spent(dsn))
    after = _decide_many(cluster, remaining + 10, amount=1, workers=4)
    assert after.count("allow") == remaining  # exactly what is left, no more
    assert _spent(dsn) == 100
    assert all(v in ("allow", "block", "require_approval") for v in after), after
    _assert_verified(cluster, cluster.nodes[1])


def test_database_outage_fails_closed_and_recovers(cluster, dsn):
    name = dsn.rsplit("/", 1)[1]
    assert _decide_many(cluster, 4, amount=1, workers=2) == ["allow"] * 4

    with psycopg.connect(ADMIN_URL, autocommit=True) as admin:
        admin.execute(f'ALTER DATABASE "{name}" ALLOW_CONNECTIONS false')
        admin.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s",
            (name,),
        )
    try:
        started = time.monotonic()
        during = _decide_many(cluster, 8, amount=1, workers=8)
        took = time.monotonic() - started
        assert "allow" not in during, during  # no verdict without the ledger
        assert all(v.startswith("http_5") for v in during), during
        assert took < 15, f"requests hung for {took:.1f}s during the outage"
        for node in cluster.nodes:
            assert httpx.get(f"{node.url}/ready", timeout=10).status_code == 503
    finally:
        with psycopg.connect(ADMIN_URL, autocommit=True) as admin:
            admin.execute(f'ALTER DATABASE "{name}" ALLOW_CONNECTIONS true')

    # Recovery: connections broken by the outage fail once (5xx, never a
    # wrong verdict) and are replaced; then every request is decided again.
    deadline, streak, seen = time.monotonic() + 30, 0, []
    while streak < 6 and time.monotonic() < deadline:
        verdict = _decide_many(cluster, 1, amount=1, workers=1)[0]
        seen.append(verdict)
        assert verdict == "allow" or verdict.startswith("http_5"), seen
        streak = streak + 1 if verdict == "allow" else 0
    assert streak == 6, seen
    _assert_verified(cluster)


def test_outcome_for_a_decision_made_on_the_other_process(cluster):
    body, _wire = cluster.payment(3)
    decided = cluster.post("/v1/decide", "payer-1", body, node=cluster.nodes[0])
    assert decided.status_code == 200, decided.text
    decision_id = decided.json()["record"]["decision_id"]
    reported = cluster.post(
        "/v1/outcome",
        "payer-1",
        {"decision_id": decision_id, "status": "refused", "detail": "bank declined"},
        node=cluster.nodes[1],
    )
    assert reported.status_code == 200, reported.text
    lineage = cluster.get(
        f"/v1/lineage/{decision_id}", agent="payer-1", node=cluster.nodes[1]
    )
    assert [r["decision_id"] for r in lineage["lineage"]][-1] == decision_id
    blocked_view = cluster.get(
        "/v1/records/payer-1", agent="payer-1", node=cluster.nodes[1]
    )
    assert decision_id in {r["decision_id"] for r in blocked_view["records"]}
