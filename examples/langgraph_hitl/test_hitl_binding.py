"""Tests: a LangGraph human approval is bound to the exact tool call by PrivateVault.

Run:  uv run --no-sync pytest examples/langgraph_hitl/test_hitl_binding.py -v
"""

from __future__ import annotations

import sys
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

import agent as A  # noqa: E402, N812

from agent_dna.decision import DecisionEngine  # noqa: E402
from agent_dna.grants import GrantRegistry  # noqa: E402
from agent_dna.trace import AgentAction  # noqa: E402

TID = "thread-1"
CALL_A = {
    "id": "call-A",
    "name": "send_payment",
    "args": {"to": "acct-1", "amount": 5000, "currency": "USD"},
}
CALL_B = {
    "id": "call-B",
    "name": "send_payment",
    "args": {"to": "acct-2", "amount": 700, "currency": "USD"},
}


@pytest.fixture(autouse=True)
def _clear_sent():
    A.SENT.clear()
    yield
    A.SENT.clear()


@pytest.fixture
def gate(tmp_path):
    return A.PVGate(tmp_path / "pv.db")


def calls_of(graph, cfg):
    return graph.get_state(cfg).values["calls"]


def edit_state(graph, cfg, cid, **fields):
    graph.update_state(cfg, {"calls": {cid: fields}})


# ------------------------------------------------------------------ T1
def test_t1_happy_path(gate):
    g = A.build_graph(gate)
    cfg, out = A.start(g, TID, [CALL_A])
    pending = out["__interrupt__"][0].value
    assert pending["args"]["amount"] == 5000 and A.SENT == []

    A.approve_shown(g, cfg)
    assert A.SENT == [{"to": "acct-1", "amount": 5000, "currency": "USD"}]

    call = calls_of(g, cfg)["call-A"]
    assert call["status"] == "done"
    assert gate.store.is_execution_authorization_consumed(
        call["permit"]["execution_authorization_id"]
    )

    graph = gate.store.load_graph()
    assert (
        all(graph.verify_all().values())
        if isinstance(graph.verify_all(), dict)
        else graph.verify_all()
    )
    decisions = list(gate.store.iter_decisions())
    allows = [d for d in decisions if d["decision"] == "allow"]
    assert len(allows) == 1 and str(allows[0]["approval_ref"]).startswith("grant-")
    assert (
        allows[0]["protocol_version"].endswith("0.2")
        or "0.2" in allows[0]["protocol_version"]
    )
    assert [e["status"] for e in gate.store.iter_executions()] == ["ok"]
    assert not graph.find_blocked()


# ------------------------------------------------------------------ T2a
def test_t2a_edit_before_approval_is_blocked(gate):
    g = A.build_graph(gate)
    cfg, out = A.start(g, TID, [CALL_A])
    shown = out["__interrupt__"][0].value["action_digest"]

    edit_state(
        g, cfg, "call-A", args={"to": "acct-1", "amount": 50000, "currency": "USD"}
    )
    A.resume(
        g,
        cfg,
        {"decision": "approve", "action_digest": shown, "reviewer": "reviewer:alice"},
    )

    assert A.SENT == []
    call = calls_of(g, cfg)["call-A"]
    assert call["status"] == "blocked" and call["reason"] == "APPROVAL_DIGEST_MISMATCH"
    assert "permit" not in call
    assert not [d for d in gate.store.iter_decisions() if d["decision"] == "allow"]
    assert any(d["decision"] == "block" for d in gate.store.iter_decisions())


# ------------------------------------------------------------------ T2b (core)
def test_t2b_edit_after_approval_before_execute_is_blocked(gate):
    g = A.build_graph(gate, interrupt_before=["execute"])
    cfg, _ = A.start(g, TID, [CALL_A])
    A.approve_shown(g, cfg)
    assert g.get_state(cfg).next == ("execute",) and A.SENT == []
    permit = calls_of(g, cfg)["call-A"]["permit"]
    pid = permit["execution_authorization_id"]

    edit_state(
        g, cfg, "call-A", args={"to": "acct-1", "amount": 50000, "currency": "USD"}
    )
    g.invoke(None, cfg)

    assert A.SENT == [], "50000 must never be sent"
    call = calls_of(g, cfg)["call-A"]
    assert call["status"] == "blocked"
    assert call["reason"] == "EXECUTION_AUTHORIZATION_NON_CONFORMANT"
    assert call["failures"], "expected concrete verify failures"
    blocked = gate.store.load_graph().find_blocked()
    assert len(blocked) == 1 and blocked[0].triggered_by == "permit_binding"
    # permit burned: reverting the edit does not re-enable the approval
    assert gate.store.is_execution_authorization_consumed(pid)
    v = gate.verify_and_consume(
        TID, "call-A", {**call, "permit": permit}, CALL_A["args"]
    )
    assert not v.ok and v.reason == "EXECUTION_AUTHORIZATION_CONSUMED"
    assert A.SENT == []


# ------------------------------------------------------------------ T2c
@pytest.mark.parametrize(
    "label,fields,expect_reason",
    [
        (
            "change to",
            {"args": {"to": "evil-9", "amount": 5000, "currency": "USD"}},
            "EXECUTION_AUTHORIZATION_NON_CONFORMANT",
        ),
        (
            "extra field",
            {"args": {"to": "acct-1", "amount": 5000, "currency": "USD", "memo": "x"}},
            "EXECUTION_AUTHORIZATION_NON_CONFORMANT",
        ),
        (
            "amount as string",
            {"args": {"to": "acct-1", "amount": "5000", "currency": "USD"}},
            "EXECUTION_AUTHORIZATION_NON_CONFORMANT",
        ),
        (
            "amount as float",
            {"args": {"to": "acct-1", "amount": 5000.0, "currency": "USD"}},
            "SCHEMA_INVALID",
        ),  # verify() reports floats as SCHEMA_INVALID rather than raising
        (
            "tool renamed",
            {"name": "wire_transfer"},
            "EXECUTION_AUTHORIZATION_NON_CONFORMANT",
        ),
    ],
)
def test_t2c_mutation_variants_blocked(gate, label, fields, expect_reason):
    g = A.build_graph(gate, interrupt_before=["execute"])
    cfg, _ = A.start(g, TID, [CALL_A])
    A.approve_shown(g, cfg)
    edit_state(g, cfg, "call-A", **fields)
    g.invoke(None, cfg)  # must not crash the graph
    assert A.SENT == [], label
    call = calls_of(g, cfg)["call-A"]
    assert call["status"] == "blocked" and call["reason"] == expect_reason, (
        label,
        call["reason"],
    )
    assert gate.store.load_graph().find_blocked(), label


def test_t6_cross_thread_permit_rejected(gate):
    g = A.build_graph(gate, interrupt_before=["execute"])
    cfg, _ = A.start(g, TID, [CALL_A])
    A.approve_shown(g, cfg)
    call = calls_of(g, cfg)["call-A"]
    v = gate.verify_and_consume("thread-2", "call-A", call, CALL_A["args"])
    assert not v.ok and v.reason == "EXECUTION_AUTHORIZATION_NON_CONFORMANT"
    assert not gate.store.is_execution_authorization_consumed(
        call["permit"]["execution_authorization_id"]
    )
    # and the legitimate thread can still execute
    g.invoke(None, cfg)
    assert len(A.SENT) == 1


# ------------------------------------------------------------------ T3
def test_t3a_replay_of_same_permit_blocked(gate):
    g = A.build_graph(gate)
    cfg, _ = A.start(g, TID, [CALL_A])
    A.approve_shown(g, cfg)
    assert len(A.SENT) == 1
    call = calls_of(g, cfg)["call-A"]

    # direct replay
    v = gate.verify_and_consume(TID, "call-A", call, CALL_A["args"])
    assert not v.ok and v.reason == "EXECUTION_AUTHORIZATION_CONSUMED"

    # fork from the pre-execute checkpoint and run execute again
    pre = [s for s in g.get_state_history(cfg) if s.next == ("execute",)]
    assert pre, "no pre-execute checkpoint found"
    g.invoke(None, pre[0].config)
    assert len(A.SENT) == 1, "replay via checkpoint fork must not pay twice"


def test_t3c_concurrent_verify_exactly_one_wins(gate):
    g = A.build_graph(gate, interrupt_before=["execute"])
    cfg, _ = A.start(g, TID, [CALL_A])
    A.approve_shown(g, cfg)
    call = calls_of(g, cfg)["call-A"]
    oks, errs = [], []

    def work():
        try:
            oks.append(gate.verify_and_consume(TID, "call-A", call, CALL_A["args"]).ok)
        except Exception as e:  # pragma: no cover
            errs.append(e)

    ts = [threading.Thread(target=work) for _ in range(6)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errs and oks.count(True) == 1


# ------------------------------------------------------------------ T4
def approve_all(g, cfg, decisions):
    """decisions: {tool_call_id: 'approve'|'reject'} answered in interrupt order."""
    while True:
        st = g.get_state(cfg)
        if not st.interrupts:
            return
        v = st.interrupts[0].value
        if decisions[v["tool_call_id"]] == "approve":
            A.resume(
                g,
                cfg,
                {
                    "decision": "approve",
                    "action_digest": v["action_digest"],
                    "reviewer": "reviewer:alice",
                },
            )
        else:
            A.resume(g, cfg, {"decision": "reject"})


def test_t4a_parallel_calls_own_permits(gate):
    g = A.build_graph(gate)
    cfg, _ = A.start(g, TID, [CALL_A, CALL_B])
    approve_all(g, cfg, {"call-A": "approve", "call-B": "approve"})
    calls = calls_of(g, cfg)
    assert sorted((s["to"], s["amount"]) for s in A.SENT) == [
        ("acct-1", 5000),
        ("acct-2", 700),
    ]
    pa, pb = calls["call-A"]["permit"], calls["call-B"]["permit"]
    assert pa["execution_authorization_id"] != pb["execution_authorization_id"]
    assert calls["call-A"]["decision_id"] != calls["call-B"]["decision_id"]
    assert (
        pa["action"]["parameters"]["amount"] == 5000
        and pb["action"]["parameters"]["amount"] == 700
    )


def test_t4b_permit_swap_rejected(gate):
    g = A.build_graph(gate, interrupt_before=["execute"])
    cfg, _ = A.start(g, TID, [CALL_A, CALL_B])
    approve_all(g, cfg, {"call-A": "approve", "call-B": "approve"})
    calls = calls_of(g, cfg)
    a, b = calls["call-A"], calls["call-B"]
    # execute A's args with B's permit (and vice versa)
    v1 = gate.verify_and_consume(TID, "call-A", {**a, "permit": b["permit"]}, a["args"])
    v2 = gate.verify_and_consume(TID, "call-B", {**b, "permit": a["permit"]}, b["args"])
    assert not v1.ok and not v2.ok
    assert v1.reason == v2.reason == "EXECUTION_AUTHORIZATION_NON_CONFORMANT"
    for c in (a, b):
        assert not gate.store.is_execution_authorization_consumed(
            c["permit"]["execution_authorization_id"]
        )
    g.invoke(None, cfg)
    assert len(A.SENT) == 2


def test_t4c_partial_approval(gate):
    g = A.build_graph(gate)
    cfg, _ = A.start(g, TID, [CALL_A, CALL_B])
    approve_all(g, cfg, {"call-A": "approve", "call-B": "reject"})
    calls = calls_of(g, cfg)
    assert A.SENT == [{"to": "acct-1", "amount": 5000, "currency": "USD"}]
    assert calls["call-A"]["status"] == "done"
    assert calls["call-B"]["status"] == "rejected" and "permit" not in calls["call-B"]
    assert (
        len([d for d in gate.store.iter_decisions() if d["decision"] == "allow"]) == 1
    )


def test_t4d_concurrent_recording_multi_writer_safe(gate):
    errs = []

    def work(i):
        try:
            gate.propose(
                TID, f"c{i}", {"to": "acct", "amount": i + 1, "currency": "USD"}
            )
        except Exception as e:
            errs.append(repr(e)[:100])

    ts = [threading.Thread(target=work, args=(i,)) for i in range(16)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert errs == []
    assert len(list(gate.store.iter_decisions())) == 16


# ------------------------------------------------------------------ T5
def test_t5_reviewer_edit_requires_new_approval(gate):
    g = A.build_graph(gate)
    cfg, out = A.start(g, TID, [CALL_A])
    first = out["__interrupt__"][0].value
    orig_decision = calls_of(g, cfg)["call-A"]["proposal_decision_id"]

    out2 = A.resume(
        g,
        cfg,
        {
            "decision": "edit",
            "args": {"to": "acct-1", "amount": 4000, "currency": "USD"},
        },
    )
    second = out2["__interrupt__"][0].value  # a SECOND interrupt, not an execution
    assert A.SENT == []
    assert (
        second["args"]["amount"] == 4000
        and second["action_digest"] != first["action_digest"]
    )
    assert calls_of(g, cfg)["call-A"]["proposal_decision_id"] != orig_decision

    A.approve_shown(g, cfg)
    assert A.SENT == [{"to": "acct-1", "amount": 4000, "currency": "USD"}]
    call = calls_of(g, cfg)["call-A"]
    assert call["permit"]["action"]["parameters"]["amount"] == 4000
    # the original 5000 proposal never got an ALLOW
    allows = [d for d in gate.store.iter_decisions() if d["decision"] == "allow"]
    assert len(allows) == 1 and allows[0]["decision_id"] != orig_decision


def test_t5b_old_digest_after_reviewer_edit_is_blocked(gate):
    g = A.build_graph(gate)
    cfg, out = A.start(g, TID, [CALL_A])
    old_digest = out["__interrupt__"][0].value["action_digest"]
    A.resume(
        g,
        cfg,
        {
            "decision": "edit",
            "args": {"to": "acct-1", "amount": 4000, "currency": "USD"},
        },
    )
    A.resume(
        g,
        cfg,
        {
            "decision": "approve",
            "action_digest": old_digest,
            "reviewer": "reviewer:alice",
        },
    )
    assert A.SENT == []
    assert calls_of(g, cfg)["call-A"]["reason"] == "APPROVAL_DIGEST_MISMATCH"


# ------------------------------------------------------------------ T7 / T8
def test_t7_expired_permit_rejected(gate):
    g = A.build_graph(gate, interrupt_before=["execute"])
    cfg, _ = A.start(g, TID, [CALL_A])
    A.approve_shown(g, cfg)
    call = calls_of(g, cfg)["call-A"]
    late = (datetime.now(UTC) + timedelta(seconds=A.PERMIT_TTL_S + 5)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    v = gate.verify_and_consume(TID, "call-A", call, CALL_A["args"], at_time=late)
    assert not v.ok and v.reason == "EXECUTION_AUTHORIZATION_NON_CONFORMANT"


def test_t8_grant_budget_refuses_bigger_amount():
    reg = GrantRegistry()
    reg.grant(
        agent_id=A.AGENT,
        capability=A.CAP,
        granted_by="r",
        budget=5000,
        expires_at=time.time() + 60,
    )
    r = DecisionEngine(authorizer=reg).decide(
        AgentAction(
            agent_id=A.AGENT,
            capability=A.CAP,
            timestamp=time.time(),
            arguments={"amount": 50000},
        )
    )
    assert r.decision.value == "require_approval"


def test_float_amount_rejected_at_propose(gate):
    g = A.build_graph(gate)
    bad = {
        "id": "c",
        "name": "send_payment",
        "args": {"to": "x", "amount": 49.99, "currency": "USD"},
    }
    cfg, out = A.start(g, TID, [bad])
    assert "__interrupt__" not in out and A.SENT == []
    assert calls_of(g, cfg)["c"]["status"] == "blocked"


# ------------------------------------------------------------------ control
def test_control_plain_langgraph_does_not_stop_the_edit():
    """Same graph shape and same interrupt(), NO PrivateVault check: the
    50000 edit made while paused after the human approved 5000 goes through."""
    g = A.build_plain_graph(interrupt_before=["execute"])
    cfg, _ = A.start(g, TID, [CALL_A])
    A.approve_shown(g, cfg)
    edit_state(
        g, cfg, "call-A", args={"to": "acct-1", "amount": 50000, "currency": "USD"}
    )
    g.invoke(None, cfg)
    assert A.SENT == [{"to": "acct-1", "amount": 50000, "currency": "USD"}]
