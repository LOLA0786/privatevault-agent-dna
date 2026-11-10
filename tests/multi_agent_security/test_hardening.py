"""Findings an outside review left open in the first version of this layer:
look-alike voter labels, key reuse, clock skew between replicas, and a
ledger that cannot be written or read."""

import os
import sqlite3
import stat
import threading
import time

import pytest

from agent_dna.consensus import ConsensusChecker, ConsensusConfig, ConsensusConfigError
from agent_dna.consensus.signing import (
    cast_vote_v2,
    consensus_action_id,
    generate_voter_keypair,
)
from agent_dna.multi_agent_security import (
    LedgerUnavailable,
    MemoryNonceLedger,
    PostgresNonceLedger,
    SqliteNonceLedger,
    TrustAnchors,
    normalize_label,
)
from agent_dna.multi_agent_security.nonce_ledger import RETENTION_GRACE

KEYS = {n: generate_voter_keypair() for n in ("a", "b", "c")}
AGENT, CAP, ARGS = "pay-agent", "payments.wire", {"amount": 5}
ACTION = consensus_action_id(AGENT, CAP, ARGS)


def roster(providers, require=2):
    return {
        "threshold": 2.0,
        "require_distinct": {"provider": require},
        "voters": [
            {"agent_id": n, "public_key": KEYS[n]["public_key"], "provider": p}
            for n, p in zip(KEYS, providers, strict=True)
        ],
    }


def votes(*names):
    return {
        "consensus": {
            "action_id": ACTION,
            "votes": [
                cast_vote_v2(
                    KEYS[n]["signing_key"], agent_id=n, action_id=ACTION, vote="APPROVE"
                )
                for n in names
            ],
        }
    }


def check(checker, evidence):
    return checker.check(evidence, agent_id=AGENT, capability=CAP, arguments=ARGS)


# ---- voter labels ----------------------------------------------------------


@pytest.mark.parametrize("variant", ["ACME", " acme ", "Acme", "acme\t", "ａｃｍｅ"])
def test_spelling_variants_are_one_provider(variant):
    assert normalize_label(variant) == "acme"


def test_variants_of_one_provider_cannot_satisfy_an_independence_rule():
    """'acme', 'ACME' and 'Acme ' are one provider: with nothing else on
    the roster a two-provider rule can never be met, so it refuses to load."""
    with pytest.raises(ConsensusConfigError, match="no quorum could ever clear"):
        ConsensusConfig.from_dict(roster(["acme", "ACME", "Acme "]))


def test_variants_do_not_count_as_distinct_at_decision_time():
    checker = ConsensusChecker(
        ConsensusConfig.from_dict(roster(["acme", "ACME ", "globex"]))
    )
    clones = check(checker, votes("a", "b"))
    assert clones.flagged and "independence_shortfall" in clones.reason
    assert not check(checker, votes("a", "c")).flagged


@pytest.mark.parametrize("label", ["аcme", "acme\u200b", "глобекс", "  "])
def test_lookalike_and_non_ascii_labels_refuse_to_load(label):
    """The first is 'acme' with a Cyrillic a."""
    with pytest.raises(ConsensusConfigError, match="printable ASCII"):
        ConsensusConfig.from_dict(roster(["acme", label, "globex"]))


# ---- one key, one identity -------------------------------------------------


def test_one_key_cannot_be_two_identities():
    key = KEYS["a"]["public_key"]
    with pytest.raises(ValueError, match="share one public key"):
        TrustAnchors(roots={"operator": key}, agents={"planner": key})
    with pytest.raises(ValueError, match="share one public key"):
        TrustAnchors(roots={"op": KEYS["b"]["public_key"]}, agents={"x": key, "y": key})
    with pytest.raises(ValueError, match="both a root and an agent"):
        TrustAnchors(roots={"same": KEYS["b"]["public_key"]}, agents={"same": key})
    with pytest.raises(ValueError, match="64 lowercase hex"):
        TrustAnchors(roots={"operator": "not-a-key"}, agents={})


# ---- clock skew between replicas -------------------------------------------


@pytest.mark.parametrize("make", [lambda p: MemoryNonceLedger(), SqliteNonceLedger])
def test_a_replica_with_a_fast_clock_does_not_free_a_spent_vote(tmp_path, make):
    """The vote expires at t+300. A replica whose clock runs 200 s ahead
    sees it as expired while a slower replica would still accept it. The
    spent record must outlive that gap."""
    ledger = make(tmp_path / "l.db")
    t = 10_000.0
    assert ledger.consume([("fraud", "n1", t + 300)], t)
    fast_clock = t + 300 + 200
    assert ledger.seen("fraud", "n1", fast_clock)
    assert not ledger.consume([("fraud", "n1", t + 300)], fast_clock)
    # another replica's unrelated write, on the fast clock, must not prune it
    assert ledger.consume([("other", "n9", fast_clock + 300)], fast_clock)
    assert ledger.seen("fraud", "n1", t + 250)  # the slow replica still sees it
    assert not ledger.seen("fraud", "n1", t + 300 + RETENTION_GRACE + 1)


# ---- a ledger that cannot be used ------------------------------------------


@pytest.mark.skipif(
    hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores file modes"
)
def test_read_only_ledger_refuses_to_start(tmp_path):
    path = tmp_path / "votes.db"
    SqliteNonceLedger(path).close()
    for item in tmp_path.iterdir():
        item.chmod(stat.S_IRUSR)
    tmp_path.chmod(stat.S_IRUSR | stat.S_IXUSR)
    try:
        with pytest.raises(LedgerUnavailable, match="not usable"):
            SqliteNonceLedger(path)
    finally:
        tmp_path.chmod(stat.S_IRWXU)


def test_corrupt_ledger_refuses_to_start(tmp_path):
    path = tmp_path / "votes.db"
    path.write_bytes(b"this is not a sqlite database" * 200)
    with pytest.raises(LedgerUnavailable, match="not usable"):
        SqliteNonceLedger(path)


class _BrokenLedger:
    def seen(self, agent_id, nonce, now):
        raise LedgerUnavailable("disk is read-only")

    def consume(self, entries, now):
        raise LedgerUnavailable("disk is read-only")

    def health(self):
        return "OperationalError: disk is read-only"


def test_ledger_failure_at_runtime_is_a_named_hold_not_a_crash_or_a_pass():
    checker = ConsensusChecker(
        ConsensusConfig.from_dict(roster(["acme", "globex", "initech"])),
        ledger=_BrokenLedger(),
    )
    result = check(checker, votes("a", "b"))
    assert result.flagged
    assert "consensus_ledger_unavailable" in result.reason
    assert checker.health() == "OperationalError: disk is read-only"


def test_ledger_that_breaks_after_startup_reports_unhealthy(tmp_path):
    ledger = SqliteNonceLedger(tmp_path / "votes.db")
    assert ledger.health() is None
    ledger._db.close()  # the storage goes away under a running process
    assert ledger.health() is not None
    with pytest.raises(LedgerUnavailable):
        ledger.consume([("a", "n", time.time() + 60)], time.time())
    with pytest.raises(LedgerUnavailable):
        ledger.seen("a", "n", time.time())


def test_ready_reports_an_unwritable_quorum_ledger(tmp_path, monkeypatch):
    import importlib
    import json

    from fastapi.testclient import TestClient

    from agent_dna.signer import generate_keypair

    server_keys = generate_keypair()
    (tmp_path / "consensus.json").write_text(
        json.dumps(roster(["acme", "globex", "initech"]))
    )
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "pv.db"))
    monkeypatch.delenv("PV_API_KEYS_FILE", raising=False)
    monkeypatch.delenv("PV_DELEGATION_FILE", raising=False)
    monkeypatch.setenv("PV_ALLOW_NO_AUTH", "1")
    monkeypatch.setenv("PV_RECEIPT_SIGNING_KEY", server_keys["signing_key"])
    monkeypatch.setenv("PV_TRUSTED_PUBLIC_KEYS", server_keys["public_key"])
    monkeypatch.setenv("PV_CONSENSUS_FILE", str(tmp_path / "consensus.json"))
    monkeypatch.setenv("PV_CONSENSUS_NONCE_DB", str(tmp_path / "votes.db"))
    import api.server as server

    importlib.reload(server)
    with TestClient(server.app) as client:
        assert client.get("/ready").status_code == 200
        core = getattr(server.state["engine"], "engine", server.state["engine"])
        core.consensus._ledger._db.close()
        not_ready = client.get("/ready")
        assert not_ready.status_code == 503
        assert not_ready.json()["reason"] == "quorum_ledger_unavailable"


# ---- PostgreSQL: replicas on separate hosts --------------------------------

PG = os.getenv("TEST_DATABASE_URL")
needs_pg = pytest.mark.skipif(
    not PG, reason="set TEST_DATABASE_URL to run the PostgreSQL tests"
)


@pytest.fixture
def pool():
    from psycopg_pool import ConnectionPool

    with ConnectionPool(PG, min_size=1, max_size=8, kwargs={"autocommit": True}) as p:
        with p.connection() as conn:
            conn.execute("DROP TABLE IF EXISTS used_votes")
        yield p
        with p.connection() as conn:
            conn.execute("DROP TABLE IF EXISTS used_votes")


@needs_pg
def test_postgres_ledger_is_all_or_nothing_and_honours_the_grace(pool):
    ledger = PostgresNonceLedger(pool)
    assert ledger.health() is None
    t = 10_000.0
    assert ledger.consume([("a", "1", t + 10)], t)
    assert not ledger.consume([("b", "2", t + 10), ("a", "1", t + 10)], t)
    assert not ledger.seen("b", "2", t)
    assert ledger.seen("a", "1", t + 11)
    later = t + 10 + RETENTION_GRACE + 1
    assert not ledger.seen("a", "1", later)
    assert ledger.consume([("a", "1", later + 30)], later)


@needs_pg
def test_postgres_replicas_racing_one_quorum_clear_it_exactly_once(pool):
    entries = [("fraud", "n1", time.time() + 300), ("legal", "n2", time.time() + 300)]
    for _ in range(5):
        with pool.connection() as conn:
            conn.execute("DROP TABLE IF EXISTS used_votes")
        replicas = [PostgresNonceLedger(pool) for _ in range(8)]
        results, barrier = [], threading.Barrier(8)

        def spend(ledger, results=results, barrier=barrier):
            barrier.wait(timeout=10)
            results.append(ledger.consume(entries, time.time()))

        threads = [threading.Thread(target=spend, args=(r,)) for r in replicas]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        assert sorted(results) == [False] * 7 + [True]


@needs_pg
def test_postgres_quorum_is_single_use_across_two_checkers(pool):
    config = ConsensusConfig.from_dict(roster(["acme", "globex", "initech"]))
    host_1 = ConsensusChecker(config, ledger=PostgresNonceLedger(pool))
    host_2 = ConsensusChecker(config, ledger=PostgresNonceLedger(pool))
    evidence = votes("a", "b")
    assert not check(host_1, evidence).flagged
    assert check(host_2, evidence).flagged


def test_sqlite_error_type_is_preserved_as_the_cause(tmp_path):
    path = tmp_path / "votes.db"
    path.write_bytes(b"x" * 4096)
    with pytest.raises(LedgerUnavailable) as raised:
        SqliteNonceLedger(path)
    assert isinstance(raised.value.__cause__, sqlite3.Error)
