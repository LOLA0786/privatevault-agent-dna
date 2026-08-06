"""
Multi-domain proof: a PROCUREMENT invariant pack on the SAME runtime.

This file contains only domain policy (invariant classes) and
declared config (roles, tool targets, corpus). It imports zero new
runtime modules and required zero changes to agent_dna/ — that
absence is the claim under test: domain = capability namespace +
invariant pack + config, same enforcer, same middleware, same chain.

Domain rules:
  1. three_way_match_before_pay — procurement.pay_* requires
     po_create + goods_receive + invoice_match earlier in the same
     execution (the classic AP control).
  2. role_gated_vendor_onboard — only procurement-role agents may
     vendor.onboard_*.
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

REQUIRED_BEFORE_PAY = {
    "procurement.po_create",
    "procurement.goods_receive",
    "procurement.invoice_match",
}


class ThreeWayMatchBeforePay(Invariant):
    name = "three_way_match_before_pay"

    def learn(self, graphs):
        pass

    def check(self, graph):
        seen = set()
        for e in sorted(graph.events, key=lambda e: e.timestamp):
            if e.intent.startswith("procurement.pay"):
                missing = REQUIRED_BEFORE_PAY - seen
                if missing:
                    return InvariantResult(
                        name=self.name,
                        passed=False,
                        severity=1.0,
                        hard=True,
                        violations=[
                            f"payment before three-way match: missing {sorted(missing)}"
                        ],
                    )
            seen.add(e.intent)
        return InvariantResult(name=self.name, passed=True)


class RoleGatedVendorOnboard(Invariant):
    name = "role_gated_vendor_onboard"

    def learn(self, graphs):
        pass

    def check(self, graph):
        offenders = sorted(
            {
                e.source
                for e in graph.events
                if e.intent.startswith("vendor.onboard")
                and e.source_role != "procurement"
            }
        )
        if offenders:
            return InvariantResult(
                name=self.name,
                passed=False,
                severity=1.0,
                hard=True,
                violations=[f"non-procurement vendor onboard: {offenders}"],
            )
        return InvariantResult(name=self.name, passed=True)


AGENTS = {
    "buyer-1": "procurement",
    "warehouse-1": "warehouse",
    "ap-clerk-1": "finance",
}


def _corpus():
    """Known-good flow: full three-way match then pay, plus a
    procurement-role vendor onboarding."""
    steps = [
        ("buyer-1", "procurement.po_create"),
        ("warehouse-1", "procurement.goods_receive"),
        ("ap-clerk-1", "procurement.invoice_match"),
        ("ap-clerk-1", "procurement.pay_invoice"),
        ("buyer-1", "vendor.onboard_new"),
    ]
    return [
        InteractionEvent(
            execution_id="corpus-p1",
            source=src,
            target="erp",
            source_role=AGENTS[src],
            target_role="erp",
            timestamp=float(i),
            intent=intent,
        )
        for i, (src, intent) in enumerate(steps, start=1)
    ]


@pytest.fixture
def stack(tmp_path):
    entries, keys = {}, {}
    for a in AGENTS:
        k = generate_key(a, scope="full")
        keys[a] = k["key"]
        entries[k["hash"]] = {"name": a, "scope": "full"}
    (tmp_path / "keys.json").write_text(json.dumps(entries))

    enforcer = CrossAgentEnforcer(
        RuntimeValidator.from_corpus(
            _corpus(),
            engine=InvariantEngine(
                [ThreeWayMatchBeforePay(), RoleGatedVendorOnboard()]
            ),
        ),
        CrossAgentConfig(
            agent_roles=AGENTS,
            tool_targets={
                "procurement": ("erp", "erp"),
                "vendor": ("vendor_registry", "registry"),
            },
        ),
    )
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


def _call(mw, keys, agent, tool, exec_id):
    return mw.handle(
        ToolCallRequest(
            adapter="test",
            tool=tool,
            api_key=keys[agent],
            context={"execution_id": exec_id},
        )
    )


def test_full_three_way_match_then_pay_not_escalated(stack):
    mw, keys = stack
    flow = [
        ("buyer-1", "procurement.po_create"),
        ("warehouse-1", "procurement.goods_receive"),
        ("ap-clerk-1", "procurement.invoice_match"),
        ("ap-clerk-1", "procurement.pay_invoice"),
    ]
    for agent, tool in flow:
        v = _call(mw, keys, agent, tool, "exec-ok")
        assert v.triggered_by != "cross_agent_invariant", (
            f"{tool} wrongly escalated: {v.reason}"
        )
        assert v.record_hash is not None


def test_pay_without_match_blocked(stack):
    mw, keys = stack
    _call(mw, keys, "buyer-1", "procurement.po_create", "exec-skip")
    v = _call(mw, keys, "ap-clerk-1", "procurement.pay_invoice", "exec-skip")
    assert v.decision == "block"
    assert v.triggered_by == "cross_agent_invariant"
    assert "three-way match" in v.reason
    rec = mw.recorder.graph.find_by_agent("ap-clerk-1")[-1]
    assert rec.record_hash == v.record_hash  # escalated verdict chained


def test_vendor_onboard_role_gated(stack):
    mw, keys = stack
    v = _call(mw, keys, "ap-clerk-1", "vendor.onboard_new", "exec-vend-1")
    assert v.decision == "block"
    assert v.triggered_by == "cross_agent_invariant"
    assert "non-procurement" in v.reason

    v = _call(mw, keys, "buyer-1", "vendor.onboard_new", "exec-vend-2")
    assert v.triggered_by != "cross_agent_invariant"
