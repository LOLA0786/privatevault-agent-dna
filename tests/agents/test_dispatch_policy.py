"""Persona policies pin each money tool to its one endpoint.

The sealed dispatch (evidence.bound.destination / evidence.bound.operation)
is what the permit binds and the receiver executes. A tool whose bytes are
aimed anywhere else is blocked by customer policy before a permit exists.
"""

from __future__ import annotations

import dataclasses
import importlib
from pathlib import Path

import pytest

from agent_dna.policy.checker import PolicyChecker
from agent_dna.policy.loader import load_policy_file
from agents.core.harness import Harness
from agents.core.model import Final, ScriptedModel, ToolCall
from agents.core.persona import load_persona

REPO = Path(__file__).resolve().parents[2]

# persona file -> (capability, destination, operation) of its money tool
PERSONAS = {
    "demos/live_checkout/persona.yaml": (
        "payments.issue_refund",
        "https://payments.gateway.example",
        "POST /v1/refunds",
    ),
    "agents/personas/finance_ops/persona.yaml": (
        "payments.pay_invoice",
        "https://payments.partner.example",
        "POST /api/v1/transfers",
    ),
    "agents/personas/property_broker/persona.yaml": (
        "payments.request_token",
        "https://escrow.partner.example",
        "POST /api/v1/token-requests",
    ),
    "agents/personas/interior_design/persona.yaml": (
        "procurement.issue_po",
        "https://procurement.vendor-network.example",
        "POST /api/v1/purchase-orders",
    ),
}


def _checker(persona_rel: str, tmp_path: Path) -> PolicyChecker:
    compiled = load_persona(REPO / persona_rel).compile(tmp_path)
    return PolicyChecker(load_policy_file(str(compiled.policy_file)))


def _bound(destination: str, operation: str) -> dict:
    return {"bound": {"destination": destination, "operation": operation}}


@pytest.mark.parametrize("persona_rel", sorted(PERSONAS))
def test_approved_endpoint_is_not_blocked_by_dispatch_rules(persona_rel, tmp_path):
    cap, dest, op = PERSONAS[persona_rel]
    result = _checker(persona_rel, tmp_path).check(
        "agent", cap, arguments={}, evidence=_bound(dest, op)
    )
    assert result.matched_rule_id not in {"wrong-destination", "wrong-operation"}


@pytest.mark.parametrize("persona_rel", sorted(PERSONAS))
@pytest.mark.parametrize(
    ("dest_override", "op_override", "rule"),
    [
        ("https://attacker.example", None, "wrong-destination"),
        (None, "DELETE /api/v1/admin/accounts", "wrong-operation"),
        (None, "POST /v1/refunds/../admin", "wrong-operation"),
    ],
)
def test_other_endpoint_is_blocked(
    persona_rel, dest_override, op_override, rule, tmp_path
):
    cap, dest, op = PERSONAS[persona_rel]
    result = _checker(persona_rel, tmp_path).check(
        "agent",
        cap,
        arguments={},
        evidence=_bound(dest_override or dest, op_override or op),
    )
    assert result.fired and result.outcome == "block"
    assert result.matched_rule_id == rule


def test_retargeted_tool_is_blocked_end_to_end(tmp_path, monkeypatch):
    """A finance_ops tool whose receiver spec is changed never gets a permit."""
    tools = importlib.import_module("agents.personas.finance_ops.tools")
    retargeted = []
    for tool in tools.TOOLS:
        if tool.name == "create_payment_instruction":
            receiver = dataclasses.replace(
                tool.receiver, operation="DELETE /api/v1/admin/accounts"
            )
            tool = dataclasses.replace(tool, receiver=receiver)
        retargeted.append(tool)
    monkeypatch.setattr(tools, "TOOLS", retargeted)

    persona = REPO / "agents" / "personas" / "finance_ops" / "persona.yaml"
    with Harness.start(persona, tmp_path / "run") as rt:
        report = rt.run_agent(
            ScriptedModel(
                [
                    ToolCall("read_invoice", {"invoice_id": "INV-1001"}),
                    ToolCall("match_purchase_order", {"invoice_id": "INV-1001"}),
                    ToolCall("create_payment_instruction", {"invoice_id": "INV-1001"}),
                    Final("done"),
                ]
            )
        )
        pay = report.step("create_payment_instruction")
        assert pay.decision == "block"
        assert pay.policy_id == "wrong-operation"
        assert pay.permit is None
        assert rt.upstream.seen() == []
