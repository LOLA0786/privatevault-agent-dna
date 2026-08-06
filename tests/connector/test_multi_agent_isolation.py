"""
Multi-agent isolation through ONE connector — Engineering Standard
rule 1: real middleware, real engine, real breaker, real registry.

Proves: N agents calling concurrently get distinct chains with no
cross-contamination; suspending one agent never blocks another;
per-agent chains all verify after concurrent load.
"""

import json
import threading
import time

import pytest

from agent_dna.apikeys import ApiKeyRegistry, generate_key
from agent_dna.circuit_breaker import BreakerConfig, CircuitBreaker, GuardedEngine
from agent_dna.connector import ConnectorMiddleware, ToolCallRequest
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.sqlite_store import SQLiteDecisionStore
from tests.test_multi_writer_safety import _engine

N_AGENTS = 6
CALLS_PER_AGENT = 15


@pytest.fixture
def swarm(tmp_path):
    keys = {}
    entries = {}
    for i in range(N_AGENTS):
        k = generate_key(f"swarm-agent-{i}", scope="full")
        keys[f"swarm-agent-{i}"] = k["key"]
        entries[k["hash"]] = {"name": f"swarm-agent-{i}", "scope": "full"}
    keys_path = tmp_path / "keys.json"
    keys_path.write_text(json.dumps(entries))

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
        recorder=DecisionRecorder(
            store=SQLiteDecisionStore(tmp_path / "decisions.db"),
            multi_writer_safe=True,
        ),
        keys=ApiKeyRegistry(str(keys_path)),
    )
    return mw, keys, breaker


def test_concurrent_agents_distinct_chains(swarm):
    mw, keys, _ = swarm
    errors = []

    def agent_loop(agent_id, key):
        try:
            for n in range(CALLS_PER_AGENT):
                v = mw.handle(
                    ToolCallRequest(
                        adapter="test",
                        tool=f"crm.read_{n}",
                        api_key=key,
                        arguments={"n": n},
                    )
                )
                assert v.agent_id == agent_id, (
                    f"identity cross-contamination: {agent_id} got {v.agent_id}"
                )
                assert v.record_hash is not None
        except Exception as e:
            errors.append((agent_id, repr(e)))

    threads = [
        threading.Thread(target=agent_loop, args=(a, k)) for a, k in keys.items()
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, errors
    # under multi_writer_safe the in-memory graph is deliberately not
    # populated -- the store is the truth. All assertions load fresh.
    # verify from a FRESH store load — same discipline as the
    # multi-writer suite: never trust any single in-memory view
    fresh = mw.recorder.store.load_graph()
    for agent_id in keys:
        assert fresh.verify_chain(agent_id), f"{agent_id} chain broken"
        assert len(fresh.find_by_agent(agent_id)) == CALLS_PER_AGENT


def test_suspension_isolated_under_concurrency(swarm):
    mw, keys, breaker = swarm
    suspended = "swarm-agent-0"
    breaker._trip(suspended, "volume_trip: test", time.time())
    results = {}

    def one_call(agent_id, key):
        results[agent_id] = mw.handle(
            ToolCallRequest(
                adapter="test",
                tool="crm.read_contact",
                api_key=key,
            )
        )

    threads = [threading.Thread(target=one_call, args=(a, k)) for a, k in keys.items()]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results[suspended].decision == "block"
    assert results[suspended].triggered_by == "circuit_breaker"
    for agent_id in keys:
        if agent_id != suspended:
            assert results[agent_id].triggered_by != "circuit_breaker", (
                f"{agent_id} caught {suspended}'s suspension"
            )
