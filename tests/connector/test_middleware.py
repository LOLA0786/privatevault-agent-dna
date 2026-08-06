"""
Connector middleware — zero mocks on the enforcement path.
Covers: identity fail-closed (no key / bad key / audit-scoped key),
allowed call recorded on chain, tripped breaker blocks pre-engine,
connector faults surface as BLOCK.
"""

import json
import time

import pytest

from agent_dna.apikeys import ApiKeyRegistry, generate_key
from agent_dna.circuit_breaker import BreakerConfig, CircuitBreaker, GuardedEngine
from agent_dna.connector import ConnectorMiddleware, ToolCallRequest
from agent_dna.decision_recorder import DecisionRecorder
from tests.test_multi_writer_safety import _engine


@pytest.fixture
def keys_file(tmp_path):
    agent = generate_key("harness-agent-01", scope="full")
    auditor = generate_key("auditor-1", scope="audit")
    path = tmp_path / "keys.json"
    path.write_text(
        json.dumps(
            {
                agent["hash"]: {"name": "harness-agent-01", "scope": "full"},
                auditor["hash"]: {"name": "auditor-1", "scope": "audit"},
            }
        )
    )
    return path, agent["key"], auditor["key"]


@pytest.fixture
def middleware(tmp_path, keys_file):
    path, agent_key, auditor_key = keys_file
    breaker = CircuitBreaker(
        tmp_path / "breaker.db",
        BreakerConfig(
            max_decisions=None,
            window_seconds=60.0,
            max_cumulative_amount=None,
            max_consecutive_refusals=None,
        ),
    )
    mw = ConnectorMiddleware(
        engine=GuardedEngine(_engine(), breaker),
        recorder=DecisionRecorder(),
        keys=ApiKeyRegistry(str(path)),
    )
    return mw, agent_key, auditor_key, breaker


def _req(key, tool="crm.read_contact", **kw):
    return ToolCallRequest(adapter="test", tool=tool, api_key=key, **kw)


def test_no_key_blocked_and_not_recorded(middleware):
    mw, *_ = middleware
    v = mw.handle(_req(None))
    assert v.decision == "block"
    assert v.triggered_by == "identity"
    assert v.record_hash is None
    assert len(mw.recorder.graph) == 0  # unauthenticated writes nothing


def test_invalid_key_blocked(middleware):
    mw, *_ = middleware
    v = mw.handle(_req("pv_not-a-real-key"))
    assert v.decision == "block"
    assert v.triggered_by == "identity"


def test_audit_scope_key_cannot_enforce(middleware):
    """The auditor credential must never pass the enforcement gate."""
    mw, _, auditor_key, _ = middleware
    v = mw.handle(_req(auditor_key))
    assert v.decision == "block"
    assert v.triggered_by == "identity"
    assert len(mw.recorder.graph) == 0


def test_allowed_call_recorded_on_chain(middleware):
    mw, agent_key, _, _ = middleware
    v = mw.handle(_req(agent_key))
    assert v.agent_id == "harness-agent-01"
    assert v.record_hash is not None
    assert v.decision in ("allow", "require_approval", "block")
    recs = mw.recorder.graph.find_by_agent("harness-agent-01")
    assert len(recs) == 1
    assert recs[-1].record_hash == v.record_hash


def test_tripped_breaker_blocks_via_connector(middleware):
    """Suspension outranks everything — through the connector too."""
    mw, agent_key, _, breaker = middleware
    for _ in range(3):
        breaker.observe("harness-agent-01", "allow", amount=500.0)
    # no volume cap configured in fixture; trip explicitly instead
    breaker._trip("harness-agent-01", "test_trip: manual", time.time())

    v = mw.handle(_req(agent_key))
    assert v.decision == "block"
    assert v.triggered_by == "circuit_breaker"
    assert v.record_hash is not None  # the refusal itself is chained


def test_connector_fault_is_block(middleware):
    mw, agent_key, _, _ = middleware

    class Bomb:
        def __getattr__(self, name):
            raise RuntimeError("boom")

    mw.engine = Bomb()  # sabotage after construction
    mw._monitors.clear()  # force monitor rebuild on bomb
    v = mw.handle(_req(agent_key))
    assert v.decision == "block"
    assert v.triggered_by in ("connector_fault", "engine_fault")
