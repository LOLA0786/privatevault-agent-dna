"""
CABI through the connector — real InvariantEngine, RuntimeValidator,
InteractionGraph; deterministic invariant policies (maker!=checker),
which are policy definitions, not mocks (Engineering Standard rule 1).
"""

import json

import pytest

from agent_dna.apikeys import ApiKeyRegistry, generate_key
from agent_dna.circuit_breaker import BreakerConfig, CircuitBreaker, GuardedEngine
from agent_dna.connector import ConnectorMiddleware, ToolCallRequest
from agent_dna.connector.cross_agent import CrossAgentConfig, CrossAgentEnforcer
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.multi_agent import InteractionEvent
from agent_dna.multi_agent.base import Invariant, InvariantResult
from agent_dna.multi_agent.invariant_engine import InvariantEngine
from agent_dna.multi_agent.runtime_validator import RuntimeValidator
from tests.test_multi_writer_safety import _engine


class MakerNotChecker(Invariant):
    """HARD breach if one agent both initiates and approves a payment
    in the same execution — the dual-control rule (RBI/PMLA shape)."""

    name = "maker_not_checker"

    def learn(self, graphs):
        pass

    def check(self, graph):
        initiators, approvers = set(), set()
        for e in graph.events:
            if e.intent.startswith("payments.initiate"):
                initiators.add(e.source)
            if e.intent.startswith("payments.approve"):
                approvers.add(e.source)
        both = initiators & approvers
        if both:
            return InvariantResult(
                name=self.name,
                passed=False,
                severity=1.0,
                hard=True,
                violations=[f"maker==checker: {sorted(both)}"],
            )
        return InvariantResult(name=self.name, passed=True)


def _mw(tmp_path, agents, enforcer):
    entries, keys = {}, {}
    for a in agents:
        k = generate_key(a, scope="full")
        keys[a] = k["key"]
        entries[k["hash"]] = {"name": a, "scope": "full"}
    (tmp_path / "keys.json").write_text(json.dumps(entries))
    breaker = CircuitBreaker(
        tmp_path / "b.db",
        BreakerConfig(
            max_decisions=None,
            max_cumulative_amount=None,
            max_consecutive_refusals=None,
        ),
    )
    mw = ConnectorMiddleware(
        engine=GuardedEngine(_engine(), breaker),
        recorder=DecisionRecorder(),
        keys=ApiKeyRegistry(str(tmp_path / "keys.json")),
        cross_agent=enforcer,
    )
    return mw, keys


@pytest.fixture
def stack(tmp_path):
    # engine requires learn() before evaluate(); train through the
    # real path (from_corpus) on a minimal known-good dual-control flow
    corpus = [
        InteractionEvent(
            execution_id="corpus-1",
            source="maker-1",
            target="payment_rail",
            source_role="maker",
            target_role="rail",
            timestamp=1.0,
            intent="payments.initiate_wire",
        ),
        InteractionEvent(
            execution_id="corpus-1",
            source="checker-1",
            target="payment_rail",
            source_role="checker",
            target_role="rail",
            timestamp=2.0,
            intent="payments.approve_wire",
        ),
    ]
    enforcer = CrossAgentEnforcer(
        RuntimeValidator.from_corpus(
            corpus, engine=InvariantEngine([MakerNotChecker()])
        ),
        CrossAgentConfig(
            agent_roles={"maker-1": "maker", "checker-1": "checker"},
            tool_targets={"payments": ("payment_rail", "rail")},
        ),
    )
    return _mw(tmp_path, ["maker-1", "checker-1"], enforcer)


def _call(mw, key, tool, execution_id=None):
    ctx = {"execution_id": execution_id} if execution_id else {}
    return mw.handle(
        ToolCallRequest(adapter="test", tool=tool, api_key=key, context=ctx)
    )


def test_dual_control_flow_not_escalated(stack):
    mw, keys = stack
    v1 = _call(mw, keys["maker-1"], "payments.initiate_wire", "exec-1")
    v2 = _call(mw, keys["checker-1"], "payments.approve_wire", "exec-1")
    for v in (v1, v2):
        assert v.triggered_by != "cross_agent_invariant"
        assert v.record_hash is not None


def test_maker_equals_checker_blocked(stack):
    mw, keys = stack
    _call(mw, keys["maker-1"], "payments.initiate_wire", "exec-2")
    v = _call(mw, keys["maker-1"], "payments.approve_wire", "exec-2")
    assert v.decision == "block"
    assert v.triggered_by == "cross_agent_invariant"
    assert "maker==checker" in v.reason
    # the escalated verdict is what got chained
    rec = mw.recorder.graph.find_by_agent("maker-1")[-1]
    assert rec.record_hash == v.record_hash


def test_no_execution_id_no_cabi(stack):
    mw, keys = stack
    _call(mw, keys["maker-1"], "payments.initiate_wire")  # no exec id
    v = _call(mw, keys["maker-1"], "payments.approve_wire")
    assert v.triggered_by != "cross_agent_invariant"


def test_executions_isolated(stack):
    mw, keys = stack
    _call(mw, keys["maker-1"], "payments.initiate_wire", "exec-A")
    v = _call(mw, keys["maker-1"], "payments.approve_wire", "exec-B")
    assert v.triggered_by != "cross_agent_invariant", (
        "invariant leaked across execution windows"
    )
