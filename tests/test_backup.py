"""Ledger backups that prove their restores (agent_dna/backup.py).

Claims -> tests:
  - A restore equals the backup table by table, chains verify, the audit
    export is byte-identical, and the restored ledger keeps working
    -> test_*_backup_restores_and_proves_itself
  - A backup taken while agents keep deciding is still exact (one exported
    snapshot for dump and fingerprint) -> test_backup_under_live_writes
  - A changed dump, an edited manifest, the wrong key, or a non-empty target
    is refused -> test_tampered_*, test_restore_refuses_a_non_empty_target
  - A restore that does not match its manifest fails, even though data
    loaded -> test_a_mismatched_restore_is_reported_as_failed
"""

from __future__ import annotations

import json
import os
import shutil
import threading
import time
import uuid
from pathlib import Path

import pytest
from nacl.signing import SigningKey

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.authority_v01 import encode_public_key, sign_document
from agent_dna.backup import (
    BackupError,
    backup_postgres,
    backup_sqlite,
    main,
    restore,
    verify_backup,
)
from agent_dna.decision import DecisionEngine
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.signer_python import ReceiptSigner, generate_keypair
from agent_dna.sqlite_store import SQLiteDecisionStore
from agent_dna.trace import AgentAction
from tests.pg_support import ADMIN_URL

_PG_BIN = "/usr/lib/postgresql/16/bin"
if Path(_PG_BIN).is_dir() and shutil.which("pg_dump") is None:
    os.environ["PATH"] = f"{_PG_BIN}{os.pathsep}{os.environ['PATH']}"


class _Scorer:
    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.0,
            severity=Severity.INFO,
            reasons=[],
        )


def _record_some(recorder: DecisionRecorder, agent: str, n: int) -> list:
    engine = DecisionEngine(scorer=_Scorer())
    out = []
    for i in range(n):
        action = AgentAction(
            agent_id=agent, capability=f"cap.{i}", timestamp=time.time()
        )
        out.append(recorder.record(action, engine.decide(action)))
    return out


@pytest.fixture
def backup_key(tmp_path):
    key = SigningKey.generate()
    path = tmp_path / "backup.key"
    path.write_bytes(bytes(key))
    return str(path), encode_public_key(key)


def _signed_recorder(store) -> DecisionRecorder:
    seed = generate_keypair()["signing_key"]
    return DecisionRecorder(store=store, signer=ReceiptSigner(seed_hex=seed))


# ---- SQLite (always runs) ----------------------------------------------------


def test_sqlite_backup_restores_and_proves_itself(tmp_path, backup_key):
    source = tmp_path / "pv.db"
    store = SQLiteDecisionStore(source)
    rec = _signed_recorder(store)
    _record_some(rec, "agent-a", 4)
    _record_some(rec, "agent-b", 3)
    key, public = backup_key
    manifest = backup_sqlite(source, tmp_path / "bk", signing_key=key)
    assert manifest["fingerprint"]["tables"]["records"]["rows"] == 7
    assert verify_backup(tmp_path / "bk", public)["signature"]
    report = restore(
        tmp_path / "bk", sqlite_path=tmp_path / "restored.db", public_key=public
    )
    assert report["verified"] and report["chains_verified"] == 2
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    store.export_jsonl(a)
    SQLiteDecisionStore(tmp_path / "restored.db").export_jsonl(b)
    assert a.read_bytes() == b.read_bytes()


def test_cli_round_trip(tmp_path, backup_key, capsys):
    source = tmp_path / "pv.db"
    _record_some(DecisionRecorder(store=SQLiteDecisionStore(source)), "agent-a", 2)
    key, public = backup_key
    assert (
        main(
            [
                "backup",
                "--sqlite",
                str(source),
                "--out",
                str(tmp_path / "bk"),
                "--signing-key",
                key,
            ]
        )
        == 0
    )
    assert main(["verify", str(tmp_path / "bk"), "--public-key", public]) == 0
    assert (
        main(["restore", str(tmp_path / "bk"), "--sqlite", str(tmp_path / "r.db")]) == 0
    )
    assert '"verified": true' in capsys.readouterr().out
    assert (
        main(["restore", str(tmp_path / "bk"), "--sqlite", str(tmp_path / "r.db")]) == 1
    )


def test_tampered_dump_and_manifest_are_refused(tmp_path, backup_key):
    source = tmp_path / "pv.db"
    _record_some(DecisionRecorder(store=SQLiteDecisionStore(source)), "agent-a", 2)
    key, public = backup_key
    backup_sqlite(source, tmp_path / "bk", signing_key=key)
    dump = tmp_path / "bk" / "ledger.sqlite3"
    original = dump.read_bytes()
    dump.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
    with pytest.raises(BackupError, match="does not match the manifest"):
        verify_backup(tmp_path / "bk")
    dump.write_bytes(original)
    manifest_path = tmp_path / "bk" / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["created_at"] = "2020-01-01T00:00:00Z"
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(BackupError, match="signature"):
        verify_backup(tmp_path / "bk")
    with pytest.raises(BackupError, match="different key"):
        verify_backup(tmp_path / "bk", encode_public_key(SigningKey.generate()))


def test_unsigned_backup_cannot_satisfy_a_required_key(tmp_path):
    source = tmp_path / "pv.db"
    _record_some(DecisionRecorder(store=SQLiteDecisionStore(source)), "agent-a", 1)
    backup_sqlite(source, tmp_path / "bk")
    assert "signature" not in verify_backup(tmp_path / "bk")
    with pytest.raises(BackupError, match="unsigned"):
        verify_backup(tmp_path / "bk", encode_public_key(SigningKey.generate()))


def test_a_mismatched_restore_is_reported_as_failed(tmp_path, backup_key):
    """Re-sign a manifest that claims one more row: the restore loads the
    data, then refuses to call it a match."""
    source = tmp_path / "pv.db"
    _record_some(DecisionRecorder(store=SQLiteDecisionStore(source)), "agent-a", 2)
    key, public = backup_key
    backup_sqlite(source, tmp_path / "bk", signing_key=key)
    path = tmp_path / "bk" / "manifest.json"
    manifest = json.loads(path.read_text())
    manifest["fingerprint"]["tables"]["records"]["rows"] += 1
    resigned = sign_document(
        {k: v for k, v in manifest.items() if k != "signature"},
        SigningKey(Path(key).read_bytes()),
        signature_field="signature",
    )
    path.write_text(json.dumps(resigned))
    with pytest.raises(BackupError, match="does not match the backup"):
        restore(tmp_path / "bk", sqlite_path=tmp_path / "r.db", public_key=public)


# ---- PostgreSQL --------------------------------------------------------------

pg = pytest.mark.skipif(
    not ADMIN_URL, reason="set TEST_DATABASE_URL to run the PostgreSQL tests"
)


@pytest.fixture
def target():
    """A second, empty database to restore into."""
    import psycopg

    from tests.conftest import _with_db

    name = f"pvrestore_{uuid.uuid4().hex[:12]}"
    with psycopg.connect(ADMIN_URL, autocommit=True) as admin:
        admin.execute(f'CREATE DATABASE "{name}"')
    try:
        yield _with_db(ADMIN_URL, name)
    finally:
        with psycopg.connect(ADMIN_URL, autocommit=True) as admin:
            admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


def _require_pg_dump():
    if shutil.which("pg_dump") is None:  # with a test database, never skip silently
        pytest.fail("pg_dump/pg_restore are required on PATH for the backup tests")


def _populate(dsn: str) -> None:
    from agent_dna.circuit_breaker import BreakerConfig, CircuitBreaker
    from agent_dna.lineage import LineageContext, LineageLedger
    from agent_dna.pg_compat import PgCompatConnection
    from agent_dna.pg_store import PostgresDecisionStore, PostgresGrantSpendLedger

    store = PostgresDecisionStore(dsn, max_size=4)
    try:
        rec = _signed_recorder(store)
        _record_some(rec, "agent-a", 4)
        _record_some(rec, "agent-b", 2)
        PostgresGrantSpendLedger(store.pool).commit_spend("grant-1", "12.50", "100")
        breaker = CircuitBreaker(
            PgCompatConnection(store.pool, "breaker"), BreakerConfig()
        )
        breaker.reserve("agent-a", "3")
        lineage = LineageLedger(PgCompatConnection(store.pool, "lineage"))
        lineage.record(
            LineageContext(agent_norm="agent-a", capability="x", intent="other", flow_id=None),
            record_hash="sha256:" + "c" * 64, decision_id="d-1", decision="allow", claimed=False,
        )  # fmt: skip
    finally:
        store.close()


@pg
def test_postgres_backup_restores_and_proves_itself(dsn, target, tmp_path, backup_key):
    _require_pg_dump()
    from agent_dna.pg_store import PostgresDecisionStore

    _populate(dsn)
    key, public = backup_key
    manifest = backup_postgres(dsn, tmp_path / "bk", signing_key=key)
    tables = manifest["fingerprint"]["tables"]
    assert {
        "records",
        "envelopes",
        "grant_spend",
        "breaker_events",
        "lineage_events",
    } <= set(tables)
    assert "password" not in json.dumps(manifest["source"])
    report = restore(tmp_path / "bk", database_url=target, public_key=public)
    assert report["verified"] and report["chains_verified"] == 2

    source, restored = PostgresDecisionStore(dsn), PostgresDecisionStore(target)
    try:
        a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
        source.export_jsonl(a)
        restored.export_jsonl(b)
        assert a.read_bytes() == b.read_bytes()
        # The restored ledger is live: sequences and chains continue.
        rec = DecisionRecorder(store=restored, multi_writer_safe=True)
        _record_some(rec, "agent-a", 1)
        assert restored.load_graph().verify_chain("agent-a")
    finally:
        source.close()
        restored.close()


@pg
def test_backup_under_live_writes(dsn, target, tmp_path):
    _require_pg_dump()
    from agent_dna.pg_store import PostgresDecisionStore

    store = PostgresDecisionStore(dsn, max_size=4)
    rec = DecisionRecorder(store=store, multi_writer_safe=True)
    _record_some(rec, "agent-a", 3)
    stop = threading.Event()
    written = []

    def keep_deciding():
        while not stop.is_set():
            written.extend(_record_some(rec, "agent-live", 1))
            time.sleep(0.005)

    writer = threading.Thread(target=keep_deciding)
    writer.start()
    try:
        time.sleep(0.2)
        manifest = backup_postgres(dsn, tmp_path / "bk")
        time.sleep(0.2)
    finally:
        stop.set()
        writer.join()
        store.close()
    in_backup = manifest["fingerprint"]["tables"]["records"]["rows"]
    assert 3 < in_backup < 3 + len(written)  # a mid-stream snapshot
    report = restore(tmp_path / "bk", database_url=target)
    assert report["verified"] and report["chains_verified"] == 2


@pg
def test_restore_refuses_a_non_empty_target(dsn, tmp_path):
    _require_pg_dump()
    _populate(dsn)
    backup_postgres(dsn, tmp_path / "bk")
    with pytest.raises(BackupError, match="not empty"):
        restore(tmp_path / "bk", database_url=dsn)
