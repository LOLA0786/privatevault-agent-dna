"""PostgresDecisionStore keeps every guarantee SQLiteDecisionStore makes.

Runs against a real PostgreSQL when TEST_DATABASE_URL is set (CI starts
one); skipped otherwise. Each test gets its own fresh database.

Covered: byte-identical export versus SQLite, multi-writer chain without
forks, single-use consume and approval claims under concurrency,
suspension ordered against consume, one mint per decision under a race,
an indeterminate outcome blocking the mint, envelope atomicity, and the
runtime selecting Postgres from PV_DATABASE_URL.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from datetime import UTC, datetime

import pytest

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.authority_v01 import sha256_digest
from agent_dna.decision import DecisionEngine
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.sqlite_store import SQLiteDecisionStore
from agent_dna.trace import AgentAction
from tests.pg_support import requires_pg

psycopg = pytest.importorskip("psycopg")
pytestmark = requires_pg

from agent_dna.pg_store import PostgresDecisionStore  # noqa: E402

NOW = datetime(2026, 10, 17, 12, 0, tzinfo=UTC)
BUNDLE = {"organisation_id": "org-demo", "bundle_version": 1}
BUNDLE_DIGEST = sha256_digest(BUNDLE)


class _Scorer:
    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.0,
            severity=Severity.INFO,
            reasons=[],
        )


def _engine() -> DecisionEngine:
    return DecisionEngine(scorer=_Scorer())


@pytest.fixture
def store(dsn):
    s = PostgresDecisionStore(dsn, max_size=24)
    yield s
    s.close()


def _record_some(recorder: DecisionRecorder, agent: str, n: int) -> list:
    engine = _engine()
    out = []
    for i in range(n):
        action = AgentAction(
            agent_id=agent, capability=f"cap.{i}", timestamp=time.time()
        )
        out.append(recorder.record(action, engine.decide(action)))
    return out


def _threads(n: int, fn) -> list:
    results: list = [None] * n
    errors: list = []

    def run(i: int) -> None:
        try:
            results[i] = fn(i)
        except Exception as e:  # noqa: BLE001 - surfaced by the assert below
            errors.append(e)

    ts = [threading.Thread(target=run, args=(i,)) for i in range(n)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errors, errors
    return results


def test_export_is_byte_identical_to_sqlite(store, tmp_path):
    sqlite = SQLiteDecisionStore(tmp_path / "ref.db")
    rec = DecisionRecorder(store=sqlite)
    _record_some(rec, "agent-a", 3)
    _record_some(rec, "agent-b", 2)
    rec.report_outcome(next(iter(sqlite.iter_decisions()))["decision_id"], "ok")
    for record in sqlite.load():
        store.append(record)

    a, b = tmp_path / "sqlite.jsonl", tmp_path / "pg.jsonl"
    sqlite.export_jsonl(a)
    store.export_jsonl(b)
    assert a.read_bytes() == b.read_bytes()
    graph = store.load_graph()
    assert graph.verify_chain("agent-a") and graph.verify_chain("agent-b")
    assert store.get_chain_head("agent-a") == sqlite.get_chain_head("agent-a")
    sqlite.close()


def test_restart_restores_the_chain(store, dsn):
    first = DecisionRecorder(store=store)
    _record_some(first, "agent-r", 2)
    reopened = PostgresDecisionStore(dsn)
    second = DecisionRecorder(store=reopened)
    _record_some(second, "agent-r", 1)
    graph = reopened.load_graph()
    assert len(graph.find_by_agent("agent-r")) == 3
    assert graph.verify_chain("agent-r")
    reopened.close()


def test_concurrent_writers_never_fork_the_chain(store):
    engine = _engine()

    def write(i: int):
        recorder = DecisionRecorder(store=store, multi_writer_safe=True)
        action = AgentAction(
            agent_id="contested", capability=f"c.{i}", timestamp=time.time()
        )
        return recorder.record(action, engine.decide(action))

    _threads(20, write)
    graph = store.load_graph()
    records = graph.find_by_agent("contested")
    assert len(records) == 20
    assert graph.verify_chain("contested")
    assert len({r.prev_hash for r in records}) == 20


def test_duplicates_are_refused_with_a_reason(store):
    recorder = DecisionRecorder(store=store)
    (decision,) = _record_some(recorder, "agent-d", 1)
    with pytest.raises(ValueError, match="duplicate record id"):
        store.append(decision)
    recorder.report_outcome(decision.decision_id, "ok")
    with pytest.raises(ValueError, match="duplicate execution event"):
        recorder.report_outcome(decision.decision_id, "ok")


def test_tampered_record_is_never_persisted(store):
    recorder = DecisionRecorder(store=DecisionRecorder().store)
    (decision,) = _record_some(recorder, "agent-t", 1)
    decision.reason = "changed after sealing"
    with pytest.raises(ValueError, match="tampered"):
        store.append(decision)
    assert store.get_decision(decision.decision_id) is None


def test_envelope_commits_with_its_record_or_not_at_all(store):
    recorder = DecisionRecorder(store=store)
    (decision,) = _record_some(recorder, "agent-e", 1)
    other = DecisionRecorder(store=SQLiteDecisionStore(":memory:"))
    (fresh,) = _record_some(other, "agent-e2", 1)
    store.append(fresh, envelope={"sig": "x"})
    assert store.get_envelope(fresh.record_hash) == {"sig": "x"}
    # same record again with an envelope: the record insert fails, so the
    # envelope must not be written either
    with pytest.raises(ValueError):
        store.append(fresh, envelope={"sig": "second"})
    assert store.get_envelope(fresh.record_hash) == {"sig": "x"}
    assert store.get_envelope(decision.record_hash) is None


def test_permit_is_consumed_exactly_once_under_a_race(store):
    results = _threads(
        16,
        lambda i: store.try_consume_execution_authorization(
            "eauth-once", organisation_id="org-demo", consumed_at=f"t{i}"
        ),
    )
    assert results.count(True) == 1
    assert store.is_execution_authorization_consumed("eauth-once")


def test_approval_is_used_exactly_once_under_a_race(store):
    results = _threads(
        16,
        lambda i: store.try_consume_approval(
            "sha256:approval", organisation_id="org-demo", consumed_at=f"t{i}"
        ),
    )
    assert results.count(True) == 1
    assert store.is_approval_consumed("sha256:approval")


def test_suspension_is_checked_inside_the_consume(store):
    scopes = (("agent", "agent-s"), ("organisation", "org-demo"))
    assert store.try_consume_unless_suspended(
        "eauth-1", organisation_id="org-demo", consumed_at="t", scopes=scopes
    ) == ("consumed", None)
    assert store.try_consume_unless_suspended(
        "eauth-1", organisation_id="org-demo", consumed_at="t", scopes=scopes
    ) == ("already_consumed", None)
    assert store.suspend(
        "agent", "agent-s", reason="incident", suspended_by="ops", suspended_at="t"
    )
    assert not store.suspend(
        "agent", "agent-s", reason="again", suspended_by="ops", suspended_at="t"
    )
    status, detail = store.try_consume_unless_suspended(
        "eauth-2", organisation_id="org-demo", consumed_at="t", scopes=scopes
    )
    assert status == "suspended" and "incident" in str(detail)
    assert not store.is_execution_authorization_consumed("eauth-2")  # burns nothing


def test_no_consume_succeeds_once_a_suspension_has_committed(store):
    """Consumers race a suspension of their agent. Any claim that starts
    after suspend() has returned must be refused; claims racing it may
    go either way, but never succeed after it."""
    scopes = (("agent", "agent-x"),)
    suspended_at: list[float] = []
    outcomes: list[tuple[float, str]] = []
    lock = threading.Lock()

    def consumer(i: int):
        for j in range(25):
            started = time.monotonic()
            status, _ = store.try_consume_unless_suspended(
                f"eauth-x-{i}-{j}",
                organisation_id="org-demo",
                consumed_at="t",
                scopes=scopes,
            )
            with lock:
                outcomes.append((started, status))

    def suspender(_):
        time.sleep(0.02)
        store.suspend(
            "agent", "agent-x", reason="r", suspended_by="ops", suspended_at="t"
        )
        suspended_at.append(time.monotonic())

    _threads(9, lambda i: suspender(i) if i == 0 else consumer(i))
    cutoff = suspended_at[0]
    late = [status for started, status in outcomes if started > cutoff]
    assert late and set(late) == {"suspended"}
    assert any(status == "consumed" for _, status in outcomes)


def _claim(store, factory):
    return store.claim_or_replay_mint(
        decision_id="dec-mint",
        organisation_id="org-demo",
        agent_id="agent-m",
        principal_id="principal-1",
        bindings_digest="bind-1",
        now=NOW,
        expires_at="2099-01-01T00:00:00Z",
        minted_at="2026-10-17T12:00:00Z",
        authorization_factory=factory,
        trust_bundle=BUNDLE,
    )


def test_one_permit_per_decision_under_a_mint_race(store):
    def factory():
        return {
            "execution_authorization_id": f"eauth-{uuid.uuid4().hex}",
            "trust_bundle_digest": BUNDLE_DIGEST,
        }

    results = _threads(12, lambda i: _claim(store, factory))
    statuses = [r[0] for r in results]
    assert statuses.count("created") == 1
    assert set(statuses) <= {"created", "replay"}
    ids = {r[1]["execution_authorization_id"] for r in results}
    assert len(ids) == 1  # every caller got the same permit


def test_indeterminate_outcome_blocks_the_mint(store, dsn):
    with psycopg.connect(dsn) as conn:
        conn.execute(
            "INSERT INTO records (kind, record_id, agent_id, decision_ref, "
            "prev_hash, record_hash, body) VALUES "
            "('execution', 'exec-1', 'agent-m', 'dec-mint', '', 'h-1', %s)",
            (json.dumps({"kind": "execution", "status": "indeterminate"}),),
        )
    status, auth, bundle = _claim(
        store,
        lambda: {
            "execution_authorization_id": "eauth-x",
            "trust_bundle_digest": BUNDLE_DIGEST,
        },
    )
    assert (status, auth, bundle) == ("indeterminate", None, None)


def test_revocation_rows_match_sqlite(store, tmp_path):
    sqlite = SQLiteDecisionStore(tmp_path / "ref.db")
    for s in (store, sqlite):
        s.suspend("agent", "a1", reason="r", suspended_by="ops", suspended_at="t")
        s.suspend(
            "authorization", "eauth-9", reason="r", suspended_by="ops", suspended_at="t"
        )
    assert sorted(store.revocation_rows()[0]) == sorted(sqlite.revocation_rows()[0])
    sqlite.close()


def test_runtime_uses_postgres_when_configured(dsn, tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from agent_dna.apikeys import generate_key
    from tests.decide_binding import decide_json

    full = generate_key("a1", scope="full")
    audit = generate_key("auditor", scope="audit")
    keys = tmp_path / "keys.json"
    keys.write_text(
        json.dumps(
            {
                full["hash"]: {"name": "a1", "scope": "full"},
                audit["hash"]: {"name": "auditor", "scope": "audit"},
            }
        )
    )
    monkeypatch.setenv("PV_API_KEYS_FILE", str(keys))
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "local.db"))
    monkeypatch.setenv("PV_DATABASE_URL", dsn)
    monkeypatch.delenv("PV_RECEIPT_SIGNING_KEY", raising=False)

    import importlib

    import api.server as server

    importlib.reload(server)
    with TestClient(server.app) as http:
        assert type(server.state["store"]).__name__ == "PostgresDecisionStore"
        http.post(
            "/v1/decide",
            json=decide_json("a1", "crm.read_contact"),
            headers={"X-API-Key": full["key"]},
        )
        runtime = http.get("/v1/runtime", headers={"X-API-Key": full["key"]}).json()
        assert "PostgreSQL" in runtime["composition"]["persistence"]["detail"]
        export = http.get("/v1/audit/export", headers={"X-API-Key": audit["key"]})
        assert export.status_code == 200 and export.text.strip()

    probe = PostgresDecisionStore(dsn)
    assert any(True for _ in probe.iter_decisions())
    probe.close()


def test_suspension_waits_for_an_in_flight_consume(store, dsn):
    """Deterministic interleaving: a consume that has already checked the
    suspension list holds its scope lock, so a suspension of that scope
    cannot commit in between -- the claim cannot land after it."""
    from agent_dna.pg_store import _lock, _scope_lock_key

    in_flight = psycopg.connect(dsn)
    cur = in_flight.cursor()
    _lock(cur, _scope_lock_key("agent", "agent-y"), shared=True)
    done = threading.Event()

    def suspend():
        store.suspend(
            "agent", "agent-y", reason="r", suspended_by="ops", suspended_at="t"
        )
        done.set()

    t = threading.Thread(target=suspend)
    t.start()
    assert not done.wait(0.5), "suspension committed while a consume was in flight"
    in_flight.commit()
    assert done.wait(5)
    t.join()
    in_flight.close()


def test_mint_waits_for_an_in_flight_execution_outcome(store, dsn):
    """An execution outcome being written for a decision holds that
    decision's lock, so the mint sees the outcome, not the state before."""
    from agent_dna.pg_store import _decision_lock_key, _lock

    writer = psycopg.connect(dsn)
    cur = writer.cursor()
    _lock(cur, _decision_lock_key("dec-mint"))
    cur.execute(
        "INSERT INTO records (kind, record_id, agent_id, decision_ref, prev_hash, "
        "record_hash, body) VALUES ('execution', 'exec-2', 'agent-m', 'dec-mint', "
        "'', 'h-2', %s)",
        (json.dumps({"kind": "execution", "status": "indeterminate"}),),
    )
    result: list = []
    t = threading.Thread(
        target=lambda: result.append(
            _claim(
                store,
                lambda: {
                    "execution_authorization_id": "eauth-y",
                    "trust_bundle_digest": BUNDLE_DIGEST,
                },
            )
        )
    )
    t.start()
    time.sleep(0.5)
    assert not result, "mint decided before the in-flight outcome committed"
    writer.commit()
    t.join(5)
    assert result and result[0][0] == "indeterminate"
    writer.close()
