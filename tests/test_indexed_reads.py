"""Routine reads are indexed queries, not a rebuild of the ledger (ADR 0029).

External review, 19 October 2026, finding 5: in multi-writer mode, records,
lineage, blocked, divergent and outcome-ownership reads loaded every record
per call.

Claims -> tests:
  - The indexed reads return exactly what the full graph returns, page by
    page, on SQLite and PostgreSQL: records by agent, blocked, divergent
    (all and per agent) and every decision's lineage
    -> test_indexed_reads_match_the_full_graph[*]
  - In multi-writer mode the API answers every routine read without
    loading the ledger -> test_api_reads_never_load_the_whole_ledger
  - Pages: limit 1..1000 (default 100), next_cursor until the last page,
    malformed cursors and limits refused -> test_api_pages_*, test_bad_*
  - Another agent's records are never listed or resolved
    -> test_reads_stay_within_the_callers_agent
  - A tampered row is refused, not served
    -> test_tampered_row_is_refused[*]
  - The planner uses the new indexes -> test_sqlite_pages_use_an_index
"""

from __future__ import annotations

import importlib
import json
import os
import sqlite3
import time
from typing import Any

import pytest

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import DecisionEngine
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.ledger_reads import (
    LedgerIntegrityError,
    lineage_from_rows,
    page_from_rows,
)
from agent_dna.open_authorizer import OpenAuthorizer
from agent_dna.sqlite_store import SQLiteDecisionStore
from agent_dna.trace import AgentAction
from tests.pg_support import ADMIN_URL

AGENTS = ("agent-a", "agent-b", "agent-c")


class _Scorer:
    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.0,
            severity=Severity.INFO,
            reasons=[],
        )


class _Invariants:
    """wire.drain is forbidden: a BLOCK."""

    def validate(self, capability, previous):
        class R:
            violated = capability == "wire.drain"
            message = "forbidden" if violated else ""

        return R()


def _populate(store) -> None:
    recorder = DecisionRecorder(store=store, multi_writer_safe=True)
    engine = DecisionEngine(
        scorer=_Scorer(), invariants=_Invariants(), authorizer=OpenAuthorizer()
    )
    for i in range(23):
        agent = AGENTS[i % 3]
        capability = "wire.drain" if i % 4 == 0 else f"crm.read.{i}"
        action = AgentAction(
            agent_id=agent, capability=capability, timestamp=time.time()
        )
        record = recorder.record(action, engine.decide(action))
        if i % 4 == 0 and i % 8 == 0:
            recorder.report_outcome(record.decision_id, "ok")  # executed anyway
        elif i % 4 == 0:
            recorder.report_outcome(record.decision_id, "refused")
        elif i % 3 == 0:
            recorder.report_outcome(record.decision_id, "ok")


def _all_pages(store, size: int, **query) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    after = 0
    while True:
        page = page_from_rows(
            store.decision_rows(after_seq=after, limit=size, **query), size
        )
        out += [r.to_dict() for r in page.records]
        if page.next_cursor is None:
            return out
        after = int(page.next_cursor)


@pytest.fixture(params=["sqlite", "postgres"])
def store(request, tmp_path):
    if request.param == "sqlite":
        s = SQLiteDecisionStore(tmp_path / "pv.db")
        yield s
        s.close()
        return
    if not ADMIN_URL:
        pytest.skip("set TEST_DATABASE_URL to run the PostgreSQL tests")
    from agent_dna.pg_store import PostgresDecisionStore

    s = PostgresDecisionStore(request.getfixturevalue("dsn"), max_size=8)
    yield s
    s.close()


@pytest.mark.parametrize("size", [1, 4, 1000])
def test_indexed_reads_match_the_full_graph(store, size):
    _populate(store)
    graph = store.load_graph()
    blocked = [r.to_dict() for r in graph.find_blocked()]
    divergent = [r.to_dict() for r in graph.find_divergent()]
    assert blocked and divergent and len(divergent) < len(blocked)
    for agent in AGENTS:
        assert _all_pages(store, size, agent_id=agent) == [
            r.to_dict() for r in graph.find_by_agent(agent)
        ]
        assert _all_pages(store, size, agent_id=agent, verdict="block") == [
            r for r in blocked if r["agent_id"] == agent
        ]
        assert _all_pages(store, size, agent_id=agent, divergent=True) == [
            r for r in divergent if r["agent_id"] == agent
        ]
    assert _all_pages(store, size, verdict="block") == blocked
    assert _all_pages(store, size, divergent=True) == divergent
    for agent in AGENTS:
        for record in graph.find_by_agent(agent):
            got = lineage_from_rows(
                store.decision_lineage_rows(record.decision_id), record.decision_id
            )
            assert [r.to_dict() for r in got] == [
                r.to_dict() for r in graph.lineage(record.decision_id)
            ]
    with pytest.raises(KeyError):
        lineage_from_rows(store.decision_lineage_rows("no-such-id"), "no-such-id")


def test_sqlite_pages_use_an_index(tmp_path):
    store = SQLiteDecisionStore(tmp_path / "pv.db")
    _populate(store)
    conn = sqlite3.connect(tmp_path / "pv.db")
    for index, query, params in (
        (
            "idx_decisions_agent_seq",
            "SELECT d.seq, d.body FROM records d WHERE d.kind = 'decision' "
            "AND d.seq > ? AND d.agent_id = ? ORDER BY d.seq LIMIT ?",
            (0, "agent-a", 5),
        ),
        (
            "idx_decisions_verdict_seq",
            "SELECT d.seq, d.body FROM records d WHERE d.kind = 'decision' "
            "AND d.seq > ? AND d.decision = ? ORDER BY d.seq LIMIT ?",
            (0, "block", 5),
        ),
    ):
        plan = " ".join(
            str(row[-1]) for row in conn.execute("EXPLAIN QUERY PLAN " + query, params)
        )
        assert index in plan, plan
        assert "TEMP B-TREE" not in plan, plan  # no sort: the index is in seq order
    conn.close()
    store.close()


# ---- the API -------------------------------------------------------------------------


@pytest.fixture()
def api(tmp_path, monkeypatch):
    """Multi-writer API on SQLite, two agents with full keys."""
    from fastapi.testclient import TestClient

    from agent_dna.apikeys import generate_key

    keys = {name: generate_key(name, "full") for name in ("agent-a", "agent-b")}
    keys_path = tmp_path / "keys.json"
    keys_path.write_text(
        json.dumps(
            {k["hash"]: {"name": k["name"], "scope": "full"} for k in keys.values()}
        )
    )
    for name in [n for n in os.environ if n.startswith("PV_")]:
        monkeypatch.delenv(name)
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "pv.db"))
    monkeypatch.setenv("PV_API_KEYS_FILE", str(keys_path))
    monkeypatch.setenv("PV_MULTI_WRITER", "1")
    store = SQLiteDecisionStore(tmp_path / "pv.db")
    _populate(store)
    store.close()
    import api.server as server

    importlib.reload(server)
    with TestClient(server.app) as client:
        yield client, {n: k["key"] for n, k in keys.items()}, server


def _get(client, key, path, **params):
    return client.get(path, headers={"X-API-Key": key}, params=params)


def test_api_reads_never_load_the_whole_ledger(api, monkeypatch):
    client, keys, server = api
    store = server.state["recorder"].store
    assert server.state["recorder"].multi_writer_safe

    def forbidden(*_a, **_k):
        raise AssertionError("a routine read loaded the whole ledger")

    monkeypatch.setattr(store, "load_graph", forbidden)
    monkeypatch.setattr(store, "load", forbidden)
    key = keys["agent-a"]
    records = _get(client, key, "/v1/records/agent-a").json()["records"]
    assert records
    last = records[-1]["decision_id"]
    assert _get(client, key, f"/v1/lineage/{last}").status_code == 200
    assert _get(client, key, "/v1/blocked").status_code == 200
    assert _get(client, key, "/v1/divergent").status_code == 200
    # agent-b's first decision (i=1 in _populate) has no outcome yet
    b_key = keys["agent-b"]
    first_b = _get(client, b_key, "/v1/records/agent-b").json()["records"][0]
    outcome = client.post(
        "/v1/outcome",
        headers={"X-API-Key": b_key},
        json={"decision_id": first_b["decision_id"], "status": "refused"},
    )
    assert outcome.status_code == 200, outcome.text


def test_api_pages_follow_next_cursor(api):
    client, keys, server = api
    key = keys["agent-a"]
    whole = _get(client, key, "/v1/records/agent-a").json()
    assert whole["next_cursor"] is None
    collected, cursor = [], None
    while True:
        params = {"limit": 2} | ({"cursor": cursor} if cursor else {})
        page = _get(client, key, "/v1/records/agent-a", **params).json()
        assert len(page["records"]) <= 2
        collected += page["records"]
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert collected == whole["records"]
    lineage = _get(client, key, f"/v1/lineage/{whole['records'][-1]['decision_id']}")
    assert lineage.json()["lineage"] == whole["records"]


@pytest.mark.parametrize(
    "params",
    [{"limit": 0}, {"limit": 1001}, {"cursor": "abc"}, {"cursor": "-1"}],
    ids=["zero", "too-many", "letters", "negative"],
)
def test_bad_limit_or_cursor_is_refused(api, params):
    client, keys, _server = api
    r = _get(client, keys["agent-a"], "/v1/blocked", **params)
    assert r.status_code == 422, r.text


def test_reads_stay_within_the_callers_agent(api):
    client, keys, _server = api
    a, b = keys["agent-a"], keys["agent-b"]
    for path, field in (("/v1/blocked", "blocked"), ("/v1/divergent", "divergent")):
        rows = _get(client, a, path).json()[field]
        assert rows and {r["agent_id"] for r in rows} == {"agent-a"}
    assert _get(client, a, "/v1/records/agent-b").status_code == 404
    b_record = _get(client, b, "/v1/records/agent-b").json()["records"][0]
    assert _get(client, a, f"/v1/lineage/{b_record['decision_id']}").status_code == 404
    assert _get(client, a, "/v1/lineage/no-such-decision").status_code == 404


@pytest.mark.parametrize("path", ["records", "lineage", "blocked"])
def test_tampered_row_is_refused(api, tmp_path, path):
    client, keys, _server = api
    key = keys["agent-a"]
    target = _get(client, key, "/v1/blocked").json()["blocked"][0]
    conn = sqlite3.connect(tmp_path / "pv.db")
    body = json.loads(
        conn.execute(
            "SELECT body FROM records WHERE record_id = ?", (target["decision_id"],)
        ).fetchone()[0]
    )
    body["decision"] = "allow"  # rewritten after sealing, verdict column kept
    conn.execute(
        "UPDATE records SET body = ? WHERE record_id = ?",
        (
            json.dumps(body, sort_keys=True, separators=(",", ":")),
            target["decision_id"],
        ),
    )
    conn.commit()
    conn.close()
    url = {
        "records": "/v1/records/agent-a",
        "lineage": f"/v1/lineage/{target['decision_id']}",
        "blocked": "/v1/blocked",
    }[path]
    r = _get(client, key, url)
    assert r.status_code == 500, r.text
    assert "failed verification" in r.text
    assert "allow" not in r.text


def test_lineage_rows_must_link(tmp_path):
    store = SQLiteDecisionStore(tmp_path / "pv.db")
    _populate(store)
    graph = store.load_graph()
    chain = graph.find_by_agent("agent-a")
    bodies = store.decision_lineage_rows(chain[-1].decision_id)
    with pytest.raises(LedgerIntegrityError, match="does not reach a root"):
        lineage_from_rows(bodies[1:], chain[-1].decision_id)
    with pytest.raises(LedgerIntegrityError, match="ends elsewhere"):
        lineage_from_rows(bodies[:-1], chain[-1].decision_id)
    store.close()
