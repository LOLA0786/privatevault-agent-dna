"""Multi-writer safety: concurrent writers racing against one
SQLite store must never fork an agent's chain. Proves the
UNIQUE(agent_id, prev_hash) constraint + append_atomic + retry loop
actually serializes concurrent writes, not just that the code runs
without error."""

import threading
import time

import pytest

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import DecisionEngine
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.sqlite_store import SQLiteDecisionStore
from agent_dna.trace import AgentAction


class StubScorer:
    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id, capability=action.capability,
            drift_score=0.0, severity=Severity.INFO, reasons=[],
        )


def _engine():
    return DecisionEngine(scorer=StubScorer())


def test_multi_writer_safe_requires_store():
    with pytest.raises(ValueError, match="requires a store"):
        DecisionRecorder(multi_writer_safe=True)


def test_multi_writer_safe_requires_compatible_store():
    from agent_dna.decision_store import DecisionStore
    with pytest.raises(ValueError, match="get_chain_head"):
        DecisionRecorder(
            store=DecisionStore("/tmp/irrelevant.jsonl"),
            multi_writer_safe=True,
        )


def test_single_writer_multi_writer_safe_mode_still_chains_correctly(tmp_path):
    """Sanity check: multi_writer_safe=True with only ONE writer must
    still produce a correct, unbroken chain -- the live-read path
    isn't just for contention, it must be correct in the simple case
    too."""
    store = SQLiteDecisionStore(tmp_path / "single.db")
    recorder = DecisionRecorder(store=store, multi_writer_safe=True)
    engine = _engine()

    for cap in ("crm.read", "email.send", "crm.update"):
        action = AgentAction(agent_id="agent-1", capability=cap,
                             timestamp=time.time())
        recorder.record(action, engine.decide(action))

    # multi-writer mode deliberately does not keep recorder.graph in
    # sync (see decision_recorder.py) -- reload fresh from the store,
    # same as every other assertion in multi-writer mode must.
    fresh_graph = store.load_graph()
    assert fresh_graph.verify_chain("agent-1")
    assert len(fresh_graph.find_by_agent("agent-1")) == 3


def test_concurrent_writers_same_agent_no_fork(tmp_path):
    """The real test: N threads simultaneously call record() for the
    SAME agent_id against ONE store. After all complete, the
    persisted chain must be a single, unbroken sequence -- exactly N
    records, no duplicates, no forks -- proven by re-loading from the
    store fresh (not trusting any single thread's in-memory view)."""
    db_path = tmp_path / "concurrent.db"
    store = SQLiteDecisionStore(db_path)
    engine = _engine()

    N_THREADS = 20
    errors = []

    def writer(thread_id):
        try:
            # each thread gets its OWN recorder -- simulating separate
            # processes, each with independent in-memory state
            local_recorder = DecisionRecorder(store=store, multi_writer_safe=True)
            action = AgentAction(
                agent_id="contested-agent",
                capability=f"action.thread_{thread_id}",
                timestamp=time.time(),
            )
            local_recorder.record(action, engine.decide(action))
        except Exception as e:
            errors.append((thread_id, e))

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(N_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"writer threads raised: {errors}"

    # reload fresh from the store -- the ONLY authoritative check.
    # Do NOT trust any single thread's local recorder.graph -- in
    # multi-writer mode, local graphs are intentionally not kept in
    # sync with what other writers committed (see decision_recorder.py).
    fresh_store = SQLiteDecisionStore(db_path)
    graph = fresh_store.load_graph()

    records = graph.find_by_agent("contested-agent")
    assert len(records) == N_THREADS, (
        f"expected {N_THREADS} records, found {len(records)} -- "
        f"a lost write would mean write contention wasn't handled"
    )

    # the load-bearing assertion: the persisted chain is genuinely
    # unbroken, verified independently of any single thread's view
    assert graph.verify_chain("contested-agent"), (
        "chain verification failed -- concurrent writers produced a "
        "forked or broken chain despite the unique constraint"
    )

    # no two records share a prev_hash (would indicate a fork that
    # somehow both succeeded -- should be structurally impossible
    # given the unique index, but assert it directly as well)
    prev_hashes = [r.prev_hash for r in records]
    assert len(prev_hashes) == len(set(prev_hashes)), (
        "duplicate prev_hash found -- the chain forked"
    )


def test_concurrent_writers_different_agents_all_succeed_independently(tmp_path):
    """Contention on DIFFERENT agents must not block each other or
    interfere -- each agent's chain is independent."""
    db_path = tmp_path / "multi_agent.db"
    store = SQLiteDecisionStore(db_path)
    engine = _engine()

    N_AGENTS = 10
    errors = []

    def writer(agent_id):
        try:
            local_recorder = DecisionRecorder(store=store, multi_writer_safe=True)
            action = AgentAction(agent_id=agent_id, capability="crm.read",
                                 timestamp=time.time())
            local_recorder.record(action, engine.decide(action))
        except Exception as e:
            errors.append((agent_id, e))

    agent_ids = [f"agent-{i}" for i in range(N_AGENTS)]
    threads = [threading.Thread(target=writer, args=(a,)) for a in agent_ids]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"writer threads raised: {errors}"

    store.close()
    fresh_store = SQLiteDecisionStore(db_path)
    graph = fresh_store.load_graph()

    assert graph.verify_all() == {a: True for a in agent_ids}


def test_append_atomic_returns_false_on_prev_hash_collision(tmp_path):
    """Direct, focused proof of the core mechanism: two records for
    the same agent claiming the same prev_hash -- the second insert
    must be rejected by the store, not silently accepted."""
    from agent_dna.decision_record import build_record

    store = SQLiteDecisionStore(tmp_path / "collision.db")
    engine = _engine()

    action1 = AgentAction(agent_id="a1", capability="crm.read", timestamp=time.time())
    rec1 = build_record(action1, engine.decide(action1))
    assert store.append_atomic(rec1)

    # two DIFFERENT records both claiming to extend from GENESIS
    action2a = AgentAction(agent_id="a2", capability="crm.read", timestamp=time.time())
    action2b = AgentAction(agent_id="a2", capability="email.send", timestamp=time.time())
    rec2a = build_record(action2a, engine.decide(action2a))
    rec2b = build_record(action2b, engine.decide(action2b))
    # both have prev_hash == GENESIS_HASH for agent a2 -- classic race
    assert rec2a.prev_hash == rec2b.prev_hash

    assert store.append_atomic(rec2a) is True
    assert store.append_atomic(rec2b) is False, (
        "second insert with a colliding (agent_id, prev_hash) should "
        "have been rejected by the unique constraint"
    )
