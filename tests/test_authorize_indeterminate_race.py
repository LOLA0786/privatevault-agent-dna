"""INDETERMINATE must be observed inside the mint write transaction."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path

from agent_dna.authority_v01 import sha256_digest
from agent_dna.sqlite_store import SQLiteDecisionStore

DECISION = "dec-indeterminate-race"
NOW = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)
EXPIRES = "2099-01-01T00:00:00Z"
MINTED = "2026-08-20T12:00:00Z"
BUNDLE = {"organisation_id": "org-demo", "bundle_version": 1}
BUNDLE_DIGEST = sha256_digest(BUNDLE)


def _factory() -> dict:
    return {
        "execution_authorization_id": "eauth-race-1",
        "nonce": "nonce-race",
        "signature": "sig-race",
        "trust_bundle_digest": BUNDLE_DIGEST,
    }


def _claim(store: SQLiteDecisionStore) -> tuple:
    return store.claim_or_replay_mint(
        decision_id=DECISION,
        organisation_id="org-demo",
        agent_id="treasury-agent",
        principal_id="principal-1",
        bindings_digest="bind-1",
        now=NOW,
        expires_at=EXPIRES,
        minted_at=MINTED,
        authorization_factory=_factory,
        trust_bundle=BUNDLE,
    )


def _mint_count(path: Path, decision_id: str = DECISION) -> int:
    conn = sqlite3.connect(path)
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM execution_authorization_mint WHERE decision_id = ?",
            (decision_id,),
        ).fetchone()
        return int(row[0])
    finally:
        conn.close()


def _insert_indeterminate(
    store: SQLiteDecisionStore, decision_id: str = DECISION
) -> None:
    body = json.dumps({"kind": "execution", "status": "indeterminate"}, sort_keys=True)
    store._conn.execute(
        "INSERT INTO records (kind, record_id, agent_id, capability, decision, "
        "decision_ref, prev_hash, record_hash, body) "
        "VALUES ('execution', ?, 'treasury-agent', NULL, NULL, ?, '', ?, ?)",
        (f"exec-{decision_id}", decision_id, f"hash-{decision_id}", body),
    )
    store._conn.commit()


def test_outcome_first_blocks_authorize_and_creates_no_mint_row(tmp_path: Path) -> None:
    db = tmp_path / "pv.db"
    store = SQLiteDecisionStore(db)
    _insert_indeterminate(store)
    result = _claim(store)
    assert result[0] == "indeterminate"
    assert result[1] is None
    assert _mint_count(db) == 0
    store.close()


def test_stale_status_read_cannot_mint_after_indeterminate_commits(
    tmp_path: Path,
) -> None:
    """Reproduce the check-then-lock race without timing sleeps.

    The first status read is held until an indeterminate outcome is
    committed, then returns None (stale). The mint transaction must
    still refuse and leave no row.
    """
    db = tmp_path / "pv.db"
    store = SQLiteDecisionStore(db)
    real_status = store.decision_execution_status
    outcome_committed = threading.Event()
    first_read_started = threading.Event()
    calls = {"n": 0}

    def stale_then_live(decision_id: str) -> str | None:
        calls["n"] += 1
        if calls["n"] == 1:
            first_read_started.set()
            assert outcome_committed.wait(timeout=5)
            return None
        return real_status(decision_id)

    store.decision_execution_status = stale_then_live  # type: ignore[method-assign]
    result_box: list[tuple] = []

    def _mint() -> None:
        result_box.append(_claim(store))

    mint_thread = threading.Thread(target=_mint)
    mint_thread.start()
    assert first_read_started.wait(timeout=5)
    _insert_indeterminate(store)
    outcome_committed.set()
    mint_thread.join(timeout=5)
    assert not mint_thread.is_alive()
    assert result_box[0][0] == "indeterminate"
    assert result_box[0][1] is None
    assert _mint_count(db) == 0
    store.close()


def test_mint_first_leaves_exactly_one_authorization(tmp_path: Path) -> None:
    db = tmp_path / "pv.db"
    store = SQLiteDecisionStore(db)
    created = _claim(store)
    assert created[0] == "created"
    _insert_indeterminate(store)
    replay = _claim(store)
    assert replay[0] == "indeterminate"
    assert _mint_count(db) == 1
    store.close()


def test_concurrent_claims_converge_on_one_permit(tmp_path: Path) -> None:
    db = tmp_path / "pv.db"
    store = SQLiteDecisionStore(db)
    barrier = threading.Barrier(8, timeout=5)
    results: list[tuple] = []
    lock = threading.Lock()
    counter = {"n": 0}

    def factory() -> dict:
        with lock:
            counter["n"] += 1
            n = counter["n"]
        return {
            "execution_authorization_id": f"eauth-{n}",
            "nonce": f"nonce-{n}",
            "signature": f"sig-{n}",
            "trust_bundle_digest": BUNDLE_DIGEST,
        }

    def _race() -> None:
        barrier.wait()
        result = store.claim_or_replay_mint(
            decision_id="dec-converge",
            organisation_id="org-demo",
            agent_id="treasury-agent",
            principal_id="principal-1",
            bindings_digest="bind-1",
            now=NOW,
            expires_at=EXPIRES,
            minted_at=MINTED,
            authorization_factory=factory,
            trust_bundle=BUNDLE,
        )
        with lock:
            results.append(result)

    threads = [threading.Thread(target=_race) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
        assert not thread.is_alive()
    statuses = {item[0] for item in results}
    assert statuses <= {"created", "replay"}
    assert sum(1 for item in results if item[0] == "created") == 1
    ids = {item[1]["execution_authorization_id"] for item in results if item[1]}
    assert len(ids) == 1
    assert _mint_count(db, "dec-converge") == 1
    store.close()


def test_indeterminate_refusal_survives_restart(tmp_path: Path) -> None:
    db = tmp_path / "pv.db"
    store = SQLiteDecisionStore(db)
    _insert_indeterminate(store)
    first = _claim(store)
    assert first[0] == "indeterminate"
    store.close()
    restarted = SQLiteDecisionStore(db)
    second = _claim(restarted)
    assert second[0] == "indeterminate"
    assert second[1] is None
    assert _mint_count(db) == 0
    restarted.close()


def test_mint_then_indeterminate_survives_restart(tmp_path: Path) -> None:
    db = tmp_path / "pv.db"
    store = SQLiteDecisionStore(db)
    created = _claim(store)
    assert created[0] == "created"
    _insert_indeterminate(store)
    store.close()
    restarted = SQLiteDecisionStore(db)
    replay = _claim(restarted)
    assert replay[0] == "indeterminate"
    assert _mint_count(db) == 1
    restarted.close()
