"""Independence rules and the shared single-use ledger, through the real
ConsensusChecker and the real server."""

import importlib
import json
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import pytest
from fastapi.testclient import TestClient

from agent_dna.consensus import ConsensusChecker, ConsensusConfig, ConsensusConfigError
from agent_dna.consensus.signing import (
    cast_vote_v2,
    consensus_action_id,
    generate_voter_keypair,
)
from agent_dna.multi_agent_security import (
    LedgerUnavailable,
    MemoryNonceLedger,
    SqliteNonceLedger,
    independence_shortfall,
)
from agent_dna.multi_agent_security.nonce_ledger import RETENTION_GRACE
from agent_dna.signer import generate_keypair
from tests.decide_binding import decide_json

AGENT, CAP, ARGS = "pay-agent", "payments.pay_invoice", {"amount": 9_000_000}
ACTION_ID = consensus_action_id(AGENT, CAP, ARGS)
KEYS = {n: generate_voter_keypair() for n in ("fraud", "finance", "legal")}
# fraud and finance are the same model from the same provider and operator
PROFILE = {
    "fraud": {"model": "m-large", "provider": "acme", "operator": "bank"},
    "finance": {"model": "m-large", "provider": "acme", "operator": "bank"},
    "legal": {"model": "other-xl", "provider": "globex", "operator": "outside-firm"},
}


def roster(require_distinct=None, profile=PROFILE):
    raw = {
        "threshold": 2.0,
        "voters": [
            {
                "agent_id": n,
                "weight": 1.0,
                "public_key": k["public_key"],
                **(profile.get(n, {})),
            }
            for n, k in KEYS.items()
        ],
    }
    if require_distinct is not None:
        raw["require_distinct"] = require_distinct
    return raw


def votes(*names):
    return {
        "consensus": {
            "action_id": ACTION_ID,
            "votes": [
                cast_vote_v2(
                    KEYS[n]["signing_key"],
                    agent_id=n,
                    action_id=ACTION_ID,
                    vote="APPROVE",
                )
                for n in names
            ],
        }
    }


def check(checker, evidence):
    return checker.check(evidence, agent_id=AGENT, capability=CAP, arguments=ARGS)


# ---- independence ----------------------------------------------------------


def test_two_clones_reach_the_threshold_but_not_independence():
    checker = ConsensusChecker(
        ConsensusConfig.from_dict(roster({"provider": 2, "operator": 2}))
    )
    clones = check(checker, votes("fraud", "finance"))
    assert clones.flagged
    assert "independence_shortfall" in clones.reason
    assert "provider: approving voters span 1 distinct value(s), 2 required" in (
        clones.reason
    )
    assert not check(checker, votes("fraud", "legal")).flagged


def test_without_a_rule_the_same_two_clones_clear():
    """The rule is what makes the difference, not the labels."""
    checker = ConsensusChecker(ConsensusConfig.from_dict(roster()))
    assert not check(checker, votes("fraud", "finance")).flagged


def test_undeclared_voters_cannot_satisfy_a_rule_by_omission():
    assert independence_shortfall(
        ["a", "b"], {"a": {"provider": "acme"}, "b": {}}, {"provider": 2}
    )
    assert not independence_shortfall(
        ["a", "b"],
        {"a": {"provider": "acme"}, "b": {"provider": "globex"}},
        {"provider": 2},
    )


def test_a_failed_independence_check_does_not_burn_the_votes():
    checker = ConsensusChecker(ConsensusConfig.from_dict(roster({"provider": 2})))
    evidence = votes("fraud", "finance", "legal")
    partial = {
        "consensus": {
            **evidence["consensus"],
            "votes": evidence["consensus"]["votes"][:2],
        }
    }
    assert check(checker, partial).flagged
    assert not check(checker, evidence).flagged


@pytest.mark.parametrize(
    "rule, message",
    [
        ({"colour": 2}, "is not one of"),
        ({"provider": 1}, "at least 2"),
        ({"provider": True}, "at least 2"),
        ({"provider": 3}, "no quorum could ever clear"),
    ],
)
def test_unusable_rules_refuse_to_load(rule, message):
    with pytest.raises(ConsensusConfigError, match=message):
        ConsensusConfig.from_dict(roster(rule))


def test_unknown_voter_fields_refuse_to_load():
    raw = roster()
    raw["voters"][0]["modle"] = "typo"
    with pytest.raises(ConsensusConfigError, match="unknown field"):
        ConsensusConfig.from_dict(raw)


# ---- single use across replicas -------------------------------------------


def test_separate_processes_without_a_shared_ledger_each_clear_once():
    """The gap: two replicas, two memories."""
    config = ConsensusConfig.from_dict(roster())
    evidence = votes("fraud", "legal")
    assert not check(ConsensusChecker(config), evidence).flagged
    assert not check(ConsensusChecker(config), evidence).flagged


def test_shared_ledger_makes_a_cleared_quorum_single_use_everywhere(tmp_path):
    config = ConsensusConfig.from_dict(roster())
    path = tmp_path / "votes.db"
    replica_1 = ConsensusChecker(config, ledger=SqliteNonceLedger(path))
    replica_2 = ConsensusChecker(config, ledger=SqliteNonceLedger(path))
    evidence = votes("fraud", "legal")
    assert not check(replica_1, evidence).flagged
    replayed = check(replica_2, evidence)
    assert replayed.flagged
    assert "quorum_shortfall" in replayed.reason


def test_racing_replicas_cannot_both_consume_the_same_votes(tmp_path):
    path = tmp_path / "votes.db"
    entries = [("fraud", "n1", time.time() + 300), ("legal", "n2", time.time() + 300)]
    barrier = threading.Barrier(8, timeout=10)

    def replica(_):
        ledger = None
        try:
            ledger = SqliteNonceLedger(path)
            barrier.wait()
            return ledger.consume(entries, time.time())
        except BaseException:
            # An initialization failure must fail the test, not strand all
            # the remaining workers at an unbounded barrier/join.
            barrier.abort()
            raise
        finally:
            if ledger is not None:
                ledger.close()

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(replica, range(8)))
    assert sorted(results) == [False] * 7 + [True]


def test_wal_initialization_retries_transient_busy_only(tmp_path, monkeypatch):
    connection = sqlite3.connect(tmp_path / "busy.db", isolation_level=None)
    wrapped = Mock(wraps=connection)
    busy = sqlite3.OperationalError("database is locked")
    busy.sqlite_errorcode = sqlite3.SQLITE_BUSY
    calls = []

    def execute(sql, *params):
        calls.append(sql)
        if len(calls) == 1:
            raise busy
        return connection.execute(sql, *params)

    wrapped.execute.side_effect = execute
    monkeypatch.setattr(sqlite3, "connect", lambda *a, **kw: wrapped)
    ledger = SqliteNonceLedger(tmp_path / "busy.db")
    try:
        assert calls[:2] == ["PRAGMA journal_mode=WAL"] * 2
        assert ledger.consume([("a", "one", 2000)], 1000)
        assert not ledger.consume([("a", "one", 2000)], 1000)
    finally:
        ledger.close()


@pytest.mark.parametrize("code", [sqlite3.SQLITE_BUSY, sqlite3.SQLITE_CORRUPT])
def test_wal_initialization_failure_is_bounded_and_closes_connection(
    monkeypatch, tmp_path, code
):
    connection = Mock()
    error = sqlite3.OperationalError("injected initialization failure")
    error.sqlite_errorcode = code
    connection.execute.side_effect = error
    monkeypatch.setattr(sqlite3, "connect", lambda *a, **kw: connection)
    ticks = iter([0.0, 11.0])
    monkeypatch.setattr(
        "agent_dna.multi_agent_security.nonce_ledger.time.monotonic",
        lambda: next(ticks),
    )
    with pytest.raises(LedgerUnavailable, match="initialization failure") as raised:
        SqliteNonceLedger(tmp_path / "failed.db")
    assert isinstance(raised.value.__cause__, sqlite3.OperationalError)
    assert connection.execute.call_count == 1
    connection.close.assert_called_once()


@pytest.mark.parametrize("make", [lambda p: MemoryNonceLedger(), SqliteNonceLedger])
def test_ledger_is_all_or_nothing_and_forgets_expired_votes(tmp_path, make):
    ledger = make(tmp_path / "l.db")
    now = 1000.0
    assert ledger.consume([("a", "1", now + 10)], now)
    # one fresh vote alongside one spent vote: neither is recorded
    assert not ledger.consume([("b", "2", now + 10), ("a", "1", now + 10)], now)
    assert not ledger.seen("b", "2", now)
    assert ledger.seen("a", "1", now)
    # an expired vote stays spent for RETENTION_GRACE, then is forgotten
    assert ledger.seen("a", "1", now + 11)
    assert not ledger.consume([("a", "1", now + 30)], now + 11)
    later = now + 10 + RETENTION_GRACE + 1
    assert not ledger.seen("a", "1", later)
    assert ledger.consume([("a", "1", later + 30)], later)


# ---- on the real server ----------------------------------------------------

SERVER_KEYS = generate_keypair()


def _client(tmp_path, monkeypatch, config, name):
    grants = tmp_path / "grants.json"
    grants.write_text(
        json.dumps([{"agent_id": AGENT, "capability": CAP, "granted_by": "ops"}])
    )
    consensus = tmp_path / "consensus.json"
    consensus.write_text(json.dumps(config))
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / f"{name}.db"))
    monkeypatch.setenv("PV_GRANTS_FILE", str(grants))
    monkeypatch.setenv("PV_BASELINE_CAPABILITIES", CAP)
    monkeypatch.delenv("PV_API_KEYS_FILE", raising=False)
    monkeypatch.setenv("PV_ALLOW_NO_AUTH", "1")
    monkeypatch.setenv("PV_RECEIPT_SIGNING_KEY", SERVER_KEYS["signing_key"])
    monkeypatch.setenv("PV_TRUSTED_PUBLIC_KEYS", SERVER_KEYS["public_key"])
    monkeypatch.setenv("PV_CONSENSUS_FILE", str(consensus))
    monkeypatch.setenv("PV_CONSENSUS_NONCE_DB", str(tmp_path / "votes.db"))
    import api.server as server

    importlib.reload(server)
    return TestClient(server.app)


def _decide(client, evidence):
    return client.post(
        "/v1/decide", json=decide_json(AGENT, CAP, arguments=ARGS, evidence=evidence)
    )


def test_server_enforces_independence_and_reports_it(tmp_path, monkeypatch):
    config = roster({"provider": 2})
    with _client(tmp_path, monkeypatch, config, "one") as client:
        clones = _decide(client, votes("fraud", "finance"))
        assert clones.status_code == 202
        assert "independence_shortfall" in clones.json()["reason"]
        assert _decide(client, votes("finance", "legal")).status_code == 200
        detail = client.get("/v1/runtime").json()["composition"]["consensus"]["detail"]
        assert "independence: provider>=2" in detail
        assert "single-use: shared ledger" in detail


def test_a_restarted_server_still_refuses_a_spent_quorum(tmp_path, monkeypatch):
    """Process memory is gone after a restart; the shared ledger is not."""
    evidence = votes("fraud", "legal")
    with _client(tmp_path, monkeypatch, roster(), "first") as client:
        assert _decide(client, evidence).status_code == 200
    with _client(tmp_path, monkeypatch, roster(), "second") as client:
        replayed = _decide(client, evidence)
        assert replayed.status_code == 202
        assert replayed.json()["triggered_by"] == "consensus"
