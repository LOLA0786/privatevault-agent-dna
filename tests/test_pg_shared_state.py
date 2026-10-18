"""Agent baselines and cross-agent windows shared through PostgreSQL.

Before this, each API instance kept its own copy: behind a load balancer
an agent could initiate a payment on one instance and approve it on
another, and the dual-control window on the second instance would never
have seen the initiate. Runs against a real PostgreSQL when
TEST_DATABASE_URL is set (CI starts one); skipped otherwise.

Covered: window bounds and LRU identical to the in-memory store, no lost
events under concurrent appends from two instances, maker==checker caught
across instances (and missed by per-process windows), a baseline shared
by two instances that still advances only on ALLOW, and the API wiring.
"""

from __future__ import annotations

import random
import threading

import pytest

from agent_dna.advisory import Severity
from agent_dna.connector.cross_agent import (
    InMemoryWindows,
    escalate_with_cross_agent,
    production_cross_agent,
)
from agent_dna.decision import Decision, DecisionResult
from agent_dna.multi_agent import InteractionEvent
from agent_dna.runtime import RuntimeMonitor
from tests.pg_support import requires_pg
from tests.test_runtime_enforcement import _action, _monitor
from tests.test_wire_action_binding import env  # noqa: F401

psycopg = pytest.importorskip("psycopg")
pytestmark = requires_pg

from agent_dna.pg_shared_state import (  # noqa: E402
    PostgresAgentBaselines,
    PostgresWindows,
)
from agent_dna.pg_store import PostgresDecisionStore  # noqa: E402


@pytest.fixture
def pools(dsn):
    """Two independent instances: separate pools against one database."""
    a = PostgresDecisionStore(dsn, max_size=16)
    b = PostgresDecisionStore(dsn, max_size=16)
    yield a.pool, b.pool
    a.close()
    b.close()


def _event(eid: str, n: int, agent: str = "a", intent: str = "x.y") -> InteractionEvent:
    return InteractionEvent(
        execution_id=eid,
        source=agent,
        target="rail",
        timestamp=float(n),
        intent=intent,
        approval=n % 2 == 0,
        metadata={"n": n},
    )


# ---- windows -----------------------------------------------------------------


def test_window_bounds_and_lru_match_in_memory(pools):
    mem, pg = InMemoryWindows(), PostgresWindows(pools[0])
    rng = random.Random(7)
    bounds = {"max_window_events": 3, "max_executions": 2}
    for n in range(40):
        event = _event(f"e{rng.randrange(4)}", n)
        expected = mem.append(event, **bounds)
        got = pg.append(event, **bounds)
        assert got == expected
    for eid in ("e0", "e1", "e2", "e3"):
        assert pg.window(eid) == mem.window(eid)
    assert sum(bool(mem.window(f"e{i}")) for i in range(4)) == 2  # LRU applied


def test_concurrent_appends_from_two_instances_lose_nothing(pools):
    stores = [PostgresWindows(p) for p in pools]
    barrier = threading.Barrier(20)

    def go(i):
        barrier.wait()
        stores[i % 2].append(
            _event("shared", i), max_window_events=500, max_executions=10
        )

    threads = [threading.Thread(target=go, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(e.metadata["n"] for e in stores[0].window("shared")) == list(
        range(20)
    )


def _allow(agent: str, capability: str) -> DecisionResult:
    return DecisionResult(
        decision=Decision.ALLOW,
        triggered_by="baseline",
        reason="ok",
        capability=capability,
        agent_id=agent,
        drift_score=0.0,
        severity=Severity.INFO,
    )


def _self_approval_across(instances) -> DecisionResult:
    a, b = instances
    escalate_with_cross_agent(
        a,
        execution_id="wire-7",
        agent_id="maker-1",
        capability="payments.initiate_wire",
        result=_allow("maker-1", "payments.initiate_wire"),
    )
    return escalate_with_cross_agent(
        b,
        execution_id="wire-7",
        agent_id="maker-1",
        capability="payments.approve_wire",
        result=_allow("maker-1", "payments.approve_wire"),
    )


def test_maker_equals_checker_is_caught_across_instances(pools):
    shared = [production_cross_agent(window_store=PostgresWindows(p)) for p in pools]
    verdict = _self_approval_across(shared)
    assert verdict.decision is Decision.BLOCK
    assert verdict.triggered_by == "cross_agent_invariant"
    # The gap this closes: per-process windows never see the initiate.
    separate = [production_cross_agent() for _ in pools]
    assert _self_approval_across(separate).decision is Decision.ALLOW


# ---- baselines ---------------------------------------------------------------


def test_baseline_is_shared_and_advances_only_on_allow(pools):
    def monitor(pool):
        engine = _monitor().engine
        state = PostgresAgentBaselines(pool).for_agent("agent-1")
        return RuntimeMonitor(engine, state=state, max_events=2)

    a, b = monitor(pools[0]), monitor(pools[1])
    assert b.previous_capability is None
    a.process(_action("crm.read"))  # ALLOW on instance A
    assert b.previous_capability == "crm.read"  # ... seen on instance B
    b.process(_action("wire.drain"))  # BLOCK on B must not advance it
    b.process(_action("payments.initiate"))  # REQUIRE_APPROVAL: nor this
    assert a.previous_capability == "crm.read"
    b.process(_action("email.send"))
    assert a.previous_capability == "email.send"
    assert len(b.events) == 2  # bounded history


def test_api_uses_shared_state_and_bounded_monitors(dsn, monkeypatch, request):
    from tests.test_wire_action_binding import AGENT, CAP, ORG

    monkeypatch.setenv("PV_DATABASE_URL", dsn)
    env = request.getfixturevalue("env")  # noqa: F811 -- after PV_DATABASE_URL
    server = env["server"]
    runtime = server.state["runtime"]
    assert isinstance(runtime.agent_baselines, PostgresAgentBaselines)
    assert isinstance(server.state["cross_agent"].windows, PostgresWindows)
    assert "cross-agent windows" in runtime.composition["persistence"]["detail"]
    from tests.decide_binding import decide_json

    r = env["client"].post(
        "/v1/decide",
        headers={"X-API-Key": env["key"]},
        json=decide_json(AGENT, CAP, arguments={"amount": 1}, org=ORG),
    )
    assert r.status_code == 200, r.text
    monitor = server.state["monitors"][AGENT]
    assert monitor.events.maxlen == server._MONITOR_EVENTS
    assert r.json()["decision"] == "allow", r.json()["reason"]
    with psycopg.connect(dsn) as conn:
        row = conn.execute(
            "SELECT previous_capability FROM agent_baselines WHERE agent_id = %s",
            (AGENT,),
        ).fetchone()
    assert row == (CAP,)


def test_racing_initiate_and_self_approval_never_both_pass(pools):
    """The per-execution lock: whichever call commits second sees both."""
    a, b = (production_cross_agent(window_store=PostgresWindows(p)) for p in pools)
    both_passed = []
    for n in range(25):
        eid = f"race-{n}"
        barrier = threading.Barrier(2)
        out: dict[str, Decision] = {}

        def call(enforcer, capability, key, eid=eid, barrier=barrier, out=out):
            barrier.wait()
            out[key] = escalate_with_cross_agent(
                enforcer,
                execution_id=eid,
                agent_id="maker-1",
                capability=capability,
                result=_allow("maker-1", capability),
            ).decision

        threads = [
            threading.Thread(target=call, args=(a, "payments.initiate_wire", "init")),
            threading.Thread(target=call, args=(b, "payments.approve_wire", "approve")),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if out["init"] is Decision.ALLOW and out["approve"] is Decision.ALLOW:
            both_passed.append(eid)
    assert both_passed == []
