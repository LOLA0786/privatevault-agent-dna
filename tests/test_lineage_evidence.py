"""Lineage is evidence, not just server state (ADR 0021, lineage PR 3).

Every lineage row is a sealed event in a per-flow hash chain, signed by the
receipt signer. tools/verify_lineage.py re-checks the chain, the signatures
and the dual-control rule offline.
"""

from __future__ import annotations

import copy
import importlib
import json
import sqlite3
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agent_dna.apikeys import generate_key
from agent_dna.lineage import LineageLedger, lineage_event_hash
from agent_dna.signer_python import generate_keypair
from tests.decide_binding import decide_json

REPO = Path(__file__).resolve().parents[1]
VERIFIER = REPO / "tools" / "verify_lineage.py"
INITIATE, APPROVE, READ = (
    "payments.initiate_wire",
    "payments.approve_wire",
    "payments.read_balance",
)
AGENTS = ("maker-1", "checker-1")


def _verify(tmp_path, document, *keys) -> subprocess.CompletedProcess:
    path = tmp_path / "flow.json"
    path.write_text(document if isinstance(document, str) else json.dumps(document))
    args = [sys.executable, str(VERIFIER), str(path)]
    for key in keys:
        args += ["--trusted-key", key]
    return subprocess.run(args, capture_output=True, text=True)


@pytest.fixture()
def exported(tmp_path, monkeypatch):
    keys = {name: generate_key(name, "full") for name in AGENTS}
    auditor = generate_key("auditor-1", "audit")
    entries = {k["hash"]: {"name": n, "scope": "full"} for n, k in keys.items()}
    entries[auditor["hash"]] = {"name": "auditor-1", "scope": "audit"}
    (tmp_path / "keys.json").write_text(json.dumps(entries))
    (tmp_path / "grants.json").write_text(
        json.dumps(
            [
                {"agent_id": a, "capability": c, "granted_by": "test"}
                for a in AGENTS
                for c in (INITIATE, APPROVE, READ)
            ]
        )
    )
    signing = generate_keypair()
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "pv.db"))
    monkeypatch.setenv("PV_API_KEYS_FILE", str(tmp_path / "keys.json"))
    monkeypatch.setenv("PV_GRANTS_FILE", str(tmp_path / "grants.json"))
    monkeypatch.setenv("PV_BASELINE_CAPABILITIES", f"{INITIATE},{APPROVE},{READ}")
    monkeypatch.setenv("PV_RECEIPT_SIGNING_KEY", signing["signing_key"])
    monkeypatch.setenv("PV_TRUSTED_PUBLIC_KEYS", signing["public_key"])
    monkeypatch.setenv("PV_LINEAGE", "enforce")
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    import api.server as server

    importlib.reload(server)

    def decide(c, agent, capability, lineage=None):
        body = decide_json(agent, capability, arguments={"amount": 1000})
        if lineage:
            body["lineage"] = lineage
        r = c.post("/v1/decide", headers={"X-API-Key": keys[agent]["key"]}, json=body)
        assert r.status_code == 200, r.text
        return r.json()

    with TestClient(server.app) as c:
        first = decide(c, "maker-1", INITIATE)
        h = first["record"]["record_hash"]
        flow = first["lineage"]["flow_id"]
        decide(c, "checker-1", APPROVE, {"approves": h})
        decide(c, "maker-1", READ, {"parent_record_hash": h})
        r = c.get(f"/v1/flows/{flow}", headers={"X-API-Key": auditor["key"]})
        assert r.status_code == 200, r.text
        unauth = c.get(f"/v1/flows/{flow}")
        unknown = c.get("/v1/flows/flow:nope", headers={"X-API-Key": auditor["key"]})
    return r.json(), signing["public_key"], unauth, unknown


def _rehash_chain(doc):
    prev = "0" * 64
    for item in doc["events"]:
        item["event"]["prev_event_hash"] = prev
        item["event_hash"] = lineage_event_hash(item["event"])
        prev = item["event_hash"]
    return doc


def test_exported_flow_verifies_offline_with_signatures(exported, tmp_path):
    doc, key, _, _ = exported
    assert [e["event"]["seq"] for e in doc["events"]] == [1, 2, 3]
    assert all(e["envelope"] for e in doc["events"])
    r = _verify(tmp_path, doc, key)
    assert r.returncode == 0, r.stdout


def test_export_requires_auth_and_known_flow(exported):
    _, _, unauth, unknown = exported
    assert unauth.status_code == 401
    assert unknown.status_code == 404


def test_edited_event_fails(exported, tmp_path):
    doc, key, _, _ = exported
    bad = copy.deepcopy(doc)
    bad["events"][1]["event"]["decision"] = "block"
    assert _verify(tmp_path, bad).returncode == 1


def test_rehashed_forgery_fails_on_signature(exported, tmp_path):
    doc, key, _, _ = exported
    bad = copy.deepcopy(doc)
    bad["events"][1]["event"]["agent"] = "someone-else"
    _rehash_chain(bad)
    assert _verify(tmp_path, bad).returncode == 0  # chain alone is consistent
    r = _verify(tmp_path, bad, key)
    assert r.returncode == 1 and "signs a different hash" in r.stdout


def test_forged_self_approval_is_caught_even_without_keys(exported, tmp_path):
    doc, _, _, _ = exported
    bad = copy.deepcopy(doc)
    bad["events"][1]["event"]["agent"] = "maker-1"  # maker approves itself
    _rehash_chain(bad)
    r = _verify(tmp_path, bad)
    assert r.returncode == 1 and "DUAL CONTROL VIOLATION" in r.stdout


@pytest.mark.parametrize("mutation", ["delete_middle", "reorder", "truncate_all"])
def test_deleted_or_reordered_events_fail(exported, tmp_path, mutation):
    doc, key, _, _ = exported
    bad = copy.deepcopy(doc)
    if mutation == "delete_middle":
        del bad["events"][1]
    elif mutation == "reorder":
        bad["events"].reverse()
    else:
        bad["events"] = []
    assert _verify(tmp_path, bad, key).returncode == 1


def test_untrusted_key_and_duplicate_keys_fail(exported, tmp_path):
    doc, _, _, _ = exported
    other = generate_keypair()["public_key"]
    assert _verify(tmp_path, doc, other).returncode == 1
    text = json.dumps(doc)
    dup = text[:-1] + ', "flow_id": "flow:other"}'
    assert _verify(tmp_path, dup).returncode == 1


def test_concurrent_writes_never_fork_the_chain(tmp_path):
    ledger = LineageLedger(tmp_path / "pv.db")
    root = ledger.resolve(agent_id="maker-1", capability=INITIATE, lineage=None)
    flow = ledger.record(
        root, record_hash="a" * 64, decision_id="d0", decision="allow", claimed=False
    )
    errors: list[BaseException] = []

    def child(i: int) -> None:
        try:
            ctx = ledger.resolve(
                agent_id=f"agent-{i}",
                capability=READ,
                lineage={"parent_record_hash": "a" * 64},
            )
            ledger.record(
                ctx,
                record_hash=f"{i:064x}",
                decision_id=f"d{i}",
                decision="allow",
                claimed=False,
            )
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=child, args=(i,)) for i in range(1, 21)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    events = ledger.export_flow(flow)
    assert [e["event"]["seq"] for e in events] == list(range(1, 22))
    r = _verify(tmp_path, {"flow_id": flow, "events": events})
    assert r.returncode == 0, r.stdout


def test_rows_from_before_sealing_are_refused(tmp_path):
    db = tmp_path / "pv.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """CREATE TABLE lineage_events (record_hash TEXT PRIMARY KEY,
        flow_id TEXT NOT NULL, decision_id TEXT NOT NULL, agent_norm TEXT NOT NULL,
        capability TEXT NOT NULL, intent TEXT NOT NULL, decision TEXT NOT NULL,
        parent_record_hash TEXT, approves_record_hash TEXT, occurred_at REAL NOT NULL);
        INSERT INTO lineage_events VALUES ('%s','flow:x','d','maker-1',
        'payments.initiate_wire','initiate','allow',NULL,NULL,1.0);"""
        % ("b" * 64)
    )
    conn.commit()
    conn.close()
    ledger = LineageLedger(db)  # migrates the PR 2 table in place
    events = ledger.export_flow("flow:x")
    assert events[0]["event"] is None
    r = _verify(tmp_path, {"flow_id": "flow:x", "events": events})
    assert r.returncode == 1 and "not sealed" in r.stdout
