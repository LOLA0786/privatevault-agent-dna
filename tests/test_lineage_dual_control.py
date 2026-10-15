"""Server-derived lineage closes the maker != checker bypasses (ADR 0021).

The bypasses below were confirmed against execution_id-keyed CABI in the
2026-10 review. With PV_LINEAGE=enforce each one is a BLOCK.
"""

from __future__ import annotations

import importlib
import json
from contextlib import contextmanager

import pytest
from fastapi.testclient import TestClient

from agent_dna.apikeys import generate_key
from agent_dna.lineage import (
    ALREADY_APPROVED,
    APPROVE_TARGET_NOT_INITIATE,
    APPROVE_UNBOUND,
    MAKER_EQUALS_CHECKER,
    REFERENCE_UNKNOWN,
    TRIGGERED_BY_LINEAGE,
)
from tests.decide_binding import decide_json

INITIATE = "payments.initiate_wire"
APPROVE = "payments.approve_wire"
AGENTS = ("maker-1", "checker-1", "checker-2")


@pytest.fixture()
def world(tmp_path, monkeypatch):
    keys = {name: generate_key(name, "full") for name in AGENTS}
    keys_path = tmp_path / "keys.json"
    keys_path.write_text(
        json.dumps({k["hash"]: {"name": n, "scope": "full"} for n, k in keys.items()})
    )
    grants_path = tmp_path / "grants.json"
    grants_path.write_text(
        json.dumps(
            [
                {"agent_id": a, "capability": c, "granted_by": "test"}
                for a in AGENTS
                for c in (INITIATE, APPROVE)
            ]
        )
    )
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "pv.db"))
    monkeypatch.setenv("PV_API_KEYS_FILE", str(keys_path))
    monkeypatch.setenv("PV_GRANTS_FILE", str(grants_path))
    monkeypatch.setenv("PV_BASELINE_CAPABILITIES", f"{INITIATE},{APPROVE}")
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)

    @contextmanager
    def client(mode: str = "enforce"):
        monkeypatch.setenv("PV_LINEAGE", mode)
        import api.server as server

        importlib.reload(server)
        with TestClient(server.app) as c:
            yield c

    return client, {n: k["key"] for n, k in keys.items()}


def _decide(c, keys, agent, capability, *, lineage=None, execution_id=None):
    body = decide_json(
        agent,
        capability,
        arguments={"amount": 1000},
        execution_id=execution_id,
    )
    if lineage is not None:
        body["lineage"] = lineage
    return c.post("/v1/decide", headers={"X-API-Key": keys[agent]}, json=body)


def _initiate(c, keys, agent="maker-1", **kw) -> str:
    r = _decide(c, keys, agent, INITIATE, **kw)
    assert r.status_code == 200, r.text
    return r.json()["record"]["record_hash"]


def _lineage_block(r, code):
    assert r.status_code == 403, r.text
    body = r.json()
    assert body["triggered_by"] == TRIGGERED_BY_LINEAGE
    assert code in body["reason"]


def test_approve_without_reference_blocks(world):
    client, keys = world
    with client() as c:
        _initiate(c, keys)
        _lineage_block(_decide(c, keys, "checker-1", APPROVE), APPROVE_UNBOUND)


def test_maker_cannot_approve_own_initiate(world):
    client, keys = world
    with client() as c:
        h = _initiate(c, keys)
        r = _decide(c, keys, "maker-1", APPROVE, lineage={"approves": h})
        _lineage_block(r, MAKER_EQUALS_CHECKER)


def test_split_execution_ids_no_longer_bypass(world):
    """Bypass 1: initiate under id A, approve under id B."""
    client, keys = world
    with client() as c:
        h = _initiate(c, keys, execution_id="exec-A")
        r = _decide(
            c, keys, "maker-1", APPROVE, lineage={"approves": h}, execution_id="exec-B"
        )
        _lineage_block(r, MAKER_EQUALS_CHECKER)


def test_filler_events_cannot_evict_the_initiate(world):
    """Bypass 2: flood the window until the initiate is evicted."""
    client, keys = world
    with client() as c:
        h = _initiate(c, keys, execution_id="exec-1")
        for _ in range(520):
            _decide(c, keys, "maker-1", "payments.read_balance", execution_id="exec-1")
        r = _decide(
            c, keys, "maker-1", APPROVE, lineage={"approves": h}, execution_id="exec-1"
        )
        _lineage_block(r, MAKER_EQUALS_CHECKER)


def test_junk_ids_cannot_evict_other_agents_flow(world):
    """Bypass 3: open junk execution ids to evict the shared LRU."""
    client, keys = world
    with client() as c:
        h = _initiate(c, keys, execution_id="exec-real")
        for i in range(1050):
            _decide(c, keys, "checker-2", "payments.read_balance", execution_id=f"j{i}")
        r = _decide(c, keys, "maker-1", APPROVE, lineage={"approves": h})
        _lineage_block(r, MAKER_EQUALS_CHECKER)


def test_distinct_checker_approves_exactly_once(world):
    client, keys = world
    with client() as c:
        h = _initiate(c, keys)
        ok = _decide(c, keys, "checker-1", APPROVE, lineage={"approves": h})
        assert ok.status_code == 200, ok.text
        assert ok.json()["lineage"]["findings"] == []
        again = _decide(c, keys, "checker-2", APPROVE, lineage={"approves": h})
        _lineage_block(again, ALREADY_APPROVED)


def test_lineage_survives_restart(world):
    client, keys = world
    with client() as c:
        h = _initiate(c, keys)
    with client() as c:  # new process view of the same database
        r = _decide(c, keys, "maker-1", APPROVE, lineage={"approves": h})
        _lineage_block(r, MAKER_EQUALS_CHECKER)


def test_unknown_or_wrong_reference_blocks(world):
    client, keys = world
    with client() as c:
        r = _decide(c, keys, "checker-1", APPROVE, lineage={"approves": "a" * 64})
        _lineage_block(r, REFERENCE_UNKNOWN)
        read = _decide(c, keys, "maker-1", "payments.read_balance")
        not_initiate = read.json()["record"]["record_hash"]
        r = _decide(c, keys, "checker-1", APPROVE, lineage={"approves": not_initiate})
        _lineage_block(r, APPROVE_TARGET_NOT_INITIATE)


def test_approval_joins_the_initiates_flow(world):
    client, keys = world
    with client() as c:
        first = _decide(c, keys, "maker-1", INITIATE)
        flow = first.json()["lineage"]["flow_id"]
        h = first.json()["record"]["record_hash"]
        ok = _decide(c, keys, "checker-1", APPROVE, lineage={"approves": h})
        assert ok.json()["lineage"]["flow_id"] == flow == f"flow:{h}"


def test_caller_cannot_supply_a_flow_id(world):
    client, keys = world
    with client() as c:
        r = _decide(c, keys, "checker-1", APPROVE, lineage={"flow_id": "flow:mine"})
        assert r.status_code == 422


def test_shadow_reports_without_blocking(world):
    client, keys = world
    with client("shadow") as c:
        h = _initiate(c, keys)
        r = _decide(c, keys, "maker-1", APPROVE, lineage={"approves": h})
        assert r.json()["triggered_by"] != TRIGGERED_BY_LINEAGE
        codes = [f["code"] for f in r.json()["lineage"]["findings"]]
        assert codes == [MAKER_EQUALS_CHECKER]


def test_off_mode_is_unchanged(world):
    client, keys = world
    with client("off") as c:
        h = _initiate(c, keys)
        r = _decide(c, keys, "maker-1", APPROVE, lineage={"approves": h})
        assert "lineage" not in r.json()
        assert r.json()["triggered_by"] != TRIGGERED_BY_LINEAGE
