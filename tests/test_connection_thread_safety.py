"""
Pinning tests for the shared-sqlite-connection race (found 2026-07-11).

Root cause: one sqlite3 connection shared across threads with
check_same_thread=False. Concurrent cursor use corrupts results —
observed as IndexError on r[0] over an EMPTY tuple from fetchall()
inside load_graph(), raised from DecisionRecorder.restore_chains()
while another thread was mid-append.

These tests reproduce that interleaving directly and reliably enough
(50 rounds of 20 threads) that the pre-fix code fails; thread-local
connections make them deterministic passes.
"""

import threading
import time
import traceback

from agent_dna.circuit_breaker import BreakerConfig, CircuitBreaker
from agent_dna.sqlite_store import SQLiteDecisionStore


def _hammer(store_reads, store_writes, n_threads=20, rounds=50):
    """Interleave reader and writer callables across threads;
    return list of (round, thread, traceback) on first failure."""
    for rnd in range(rounds):
        errors = []

        def worker(tid, round_number=rnd, round_errors=errors):
            try:
                if tid % 2 == 0:
                    store_reads()
                else:
                    store_writes(tid)
            except Exception:
                round_errors.append((round_number, tid, traceback.format_exc()))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if errors:
            return errors
    return []


def test_store_concurrent_read_write_one_instance(tmp_path):
    """The restore_chains-vs-append race: half the threads reload the
    full graph (read path), half append records (write path), all
    through ONE store instance."""
    from agent_dna.decision_recorder import DecisionRecorder
    from agent_dna.trace import AgentAction
    from tests.test_multi_writer_safety import _engine

    store = SQLiteDecisionStore(tmp_path / "race.db")
    engine = _engine()

    def read():
        store.load_graph()

    def write(tid):
        rec = DecisionRecorder(store=store, multi_writer_safe=True)
        action = AgentAction(
            agent_id="contested-agent",
            capability=f"action.thread_{tid}",
            timestamp=time.time(),
        )
        rec.record(action, engine.decide(action))

    errors = _hammer(read, write)
    assert not errors, "shared-connection race:\n" + "\n".join(
        tb for _, _, tb in errors
    )


def test_breaker_concurrent_pregate_observe(tmp_path):
    """Same disease in the breaker: pre_gate reads racing observe
    writes on one CircuitBreaker instance must never corrupt."""
    br = CircuitBreaker(
        tmp_path / "breaker.db",
        BreakerConfig(max_decisions=None, max_consecutive_refusals=None),
    )

    def read():
        br.pre_gate("agent-x")
        br.verify_log()

    def write(tid):
        br.observe("agent-x", "allow", amount=1.0)

    errors = _hammer(read, write)
    assert not errors, "breaker shared-connection race:\n" + "\n".join(
        tb for _, _, tb in errors
    )
