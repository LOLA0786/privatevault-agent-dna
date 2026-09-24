"""ADR-0018 PR-J: suspension is checked inside the consume transaction.

A permit minted before its agent, organisation or authorization was
suspended must not be dispatched afterwards. The check and the claim
share one BEGIN IMMEDIATE transaction, so every claim ordered after a
committed suspension is refused. Claims committed earlier stand.
"""

import threading
import time

import pytest

from agent_dna.connector.adapters.exact_byte_http import (
    DISPATCH_SUSPENDED,
    ExactByteHttpDispatcher,
)
from agent_dna.sqlite_store import SQLiteDecisionStore

TS = "2026-09-24T00:00:00Z"


def _scopes(ea, agent="agent-1", org="org"):
    return (("authorization", ea), ("organisation", org), ("agent", agent))


def _consume(store, ea, agent="agent-1", org="org"):
    return store.try_consume_unless_suspended(
        ea, organisation_id=org, consumed_at=TS, scopes=_scopes(ea, agent, org)
    )


def _suspend(store, kind, sid, reason="test"):
    return store.suspend(
        kind, sid, reason=reason, suspended_by="operator", suspended_at=TS
    )


def test_suspended_agent_cannot_consume_and_permit_is_not_burned(tmp_path):
    s = SQLiteDecisionStore(tmp_path / "s.db")
    assert _suspend(s, "agent", "agent-1") is True
    status, detail = _consume(s, "ea-1")
    assert status == "suspended" and "agent:agent-1" in detail
    assert s.is_execution_authorization_consumed("ea-1") is False


def test_suspension_applies_only_to_later_claims(tmp_path):
    s = SQLiteDecisionStore(tmp_path / "s.db")
    assert _consume(s, "ea-1") == ("consumed", None)
    _suspend(s, "agent", "agent-1")
    assert _consume(s, "ea-2")[0] == "suspended"
    assert s.is_execution_authorization_consumed("ea-1") is True


def test_single_use_still_holds(tmp_path):
    s = SQLiteDecisionStore(tmp_path / "s.db")
    assert _consume(s, "ea-1") == ("consumed", None)
    assert _consume(s, "ea-1") == ("already_consumed", None)


def test_other_agents_are_unaffected(tmp_path):
    s = SQLiteDecisionStore(tmp_path / "s.db")
    _suspend(s, "agent", "agent-2")
    assert _consume(s, "ea-1", agent="agent-1") == ("consumed", None)
    assert _consume(s, "ea-2", agent="agent-2")[0] == "suspended"


def test_organisation_and_single_permit_scopes(tmp_path):
    s = SQLiteDecisionStore(tmp_path / "s.db")
    _suspend(s, "authorization", "ea-9")
    assert _consume(s, "ea-9")[0] == "suspended"
    assert _consume(s, "ea-1") == ("consumed", None)
    _suspend(s, "organisation", "org")
    assert _consume(s, "ea-2", agent="agent-7")[0] == "suspended"


def test_suspension_survives_restart(tmp_path):
    _suspend(SQLiteDecisionStore(tmp_path / "s.db"), "agent", "agent-1")
    assert _consume(SQLiteDecisionStore(tmp_path / "s.db"), "ea-1")[0] == "suspended"


def test_suspend_is_idempotent_and_keeps_first_reason(tmp_path):
    s = SQLiteDecisionStore(tmp_path / "s.db")
    assert _suspend(s, "agent", "agent-1", reason="first") is True
    assert _suspend(s, "agent", "agent-1", reason="second") is False
    assert "first" in _consume(s, "ea-1")[1]


@pytest.mark.parametrize("kind,sid", [("tenant", "x"), ("agent", ""), ("agent", None)])
def test_invalid_scopes_are_rejected(tmp_path, kind, sid):
    s = SQLiteDecisionStore(tmp_path / "s.db")
    with pytest.raises(ValueError):
        s.suspend(kind, sid, reason="r", suspended_by="op", suspended_at=TS)
    with pytest.raises(ValueError):
        s.try_consume_unless_suspended(
            "ea-1", organisation_id="org", consumed_at=TS, scopes=((kind, sid),)
        )


def test_no_claim_started_after_a_committed_suspension_succeeds(tmp_path):
    s = SQLiteDecisionStore(tmp_path / "s.db")
    suspended = threading.Event()
    results, lock = [], threading.Lock()

    def consumer(i):
        after_calls = 0
        for j in range(2000):
            started_after = suspended.is_set()
            status, _ = _consume(s, f"ea-{i}-{j}")
            with lock:
                results.append((started_after, status))
            if started_after:
                after_calls += 1
                if after_calls >= 3:
                    return
            time.sleep(0.0005)

    def suspender():
        deadline = time.time() + 10
        while time.time() < deadline:
            with lock:
                if len(results) >= 16:
                    break
            time.sleep(0.001)
        _suspend(s, "agent", "agent-1")
        suspended.set()

    threads = [threading.Thread(target=consumer, args=(i,)) for i in range(8)]
    threads.append(threading.Thread(target=suspender))
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert any(st == "consumed" for _, st in results), (
        "race never had a pre-suspension claim"
    )
    assert any(after for after, _ in results), "race never had a post-suspension claim"
    assert all(st == "suspended" for after, st in results if after)


def _bare_dispatcher(ledger):
    d = object.__new__(ExactByteHttpDispatcher)
    d.consume_ledger = ledger
    return d


def test_dispatcher_refuses_before_send_for_a_suspended_agent(tmp_path):
    s = SQLiteDecisionStore(tmp_path / "s.db")
    _suspend(s, "agent", "agent-1")
    auth = {"action": {"subject_key_id": "agent-1"}}
    res = _bare_dispatcher(s)._consume(
        "ea-1", "org", TS, None, b"wire", authorization=auth
    )
    assert res is not None and res.reason_code == DISPATCH_SUSPENDED
    assert s.is_execution_authorization_consumed("ea-1") is False


def test_dispatcher_consumes_when_not_suspended(tmp_path):
    s = SQLiteDecisionStore(tmp_path / "s.db")
    auth = {"action": {"subject_key_id": "agent-1"}}
    assert (
        _bare_dispatcher(s)._consume(
            "ea-1", "org", TS, None, b"wire", authorization=auth
        )
        is None
    )
    assert s.is_execution_authorization_consumed("ea-1") is True
