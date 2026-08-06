"""MCP gateway: same composed line, exposed for MCP tool consumption.
Tests the gateway logic directly (no MCP transport/stdio needed —
transport is a thin decorator layer, sanity-checked separately)."""

import pytest
from agent_dna.mcp_gateway import MCPGateway

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.decision import DecisionEngine
from agent_dna.decision_recorder import DecisionRecorder


class StubScorer:
    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.0,
            severity=Severity.INFO,
            reasons=[],
        )


class Invariants:
    def validate(self, capability, previous):
        class R:
            pass

        r = R()
        r.violated = capability == "storage.bulk_export"
        r.message = "forbidden" if r.violated else ""
        return r


def _gateway():
    engine = DecisionEngine(scorer=StubScorer(), invariants=Invariants())
    return MCPGateway(engine, DecisionRecorder())


def test_decide_returns_expected_shape():
    gw = _gateway()
    result = gw.decide("mcp-agent", "crm.read_contact")
    assert result["decision"] == "allow"
    assert result["triggered_by"] == "baseline"
    assert result["decision_id"]
    assert len(result["record_hash"]) == 64


def test_decide_blocks_forbidden_capability():
    gw = _gateway()
    result = gw.decide("mcp-agent", "storage.bulk_export")
    assert result["decision"] == "block"
    assert result["triggered_by"] == "invariant"


def test_report_outcome_roundtrip():
    gw = _gateway()
    d = gw.decide("mcp-agent", "crm.read_contact")
    outcome = gw.report_outcome(d["decision_id"], "ok")
    assert outcome["status"] == "ok"
    assert outcome["decision_ref"] == d["decision_id"]


def test_verify_reports_intact_chain():
    gw = _gateway()
    gw.decide("mcp-agent", "crm.read_contact")
    gw.decide("mcp-agent", "email.send")
    assert gw.verify() == {"mcp-agent": True}


def test_lineage_returns_ordered_path():
    gw = _gateway()
    gw.decide("mcp-agent", "crm.read_contact")
    d2 = gw.decide("mcp-agent", "email.send")
    path = gw.lineage(d2["decision_id"])
    assert [p["capability"] for p in path] == ["crm.read_contact", "email.send"]


def test_blocked_and_divergent_queries():
    gw = _gateway()
    gw.decide("mcp-agent", "crm.read_contact")
    blocked = gw.decide("mcp-agent", "storage.bulk_export")
    gw.report_outcome(blocked["decision_id"], "ok")  # divergence

    assert len(gw.blocked()) == 1
    assert gw.blocked()[0]["capability"] == "storage.bulk_export"
    assert len(gw.divergent()) == 1
    assert gw.divergent()[0]["capability"] == "storage.bulk_export"


def test_per_agent_baselines_do_not_cross_contaminate():
    gw = _gateway()
    gw.decide("agent-a", "storage.bulk_export")  # BLOCK for agent-a
    r = gw.decide("agent-b", "crm.read_contact")  # unrelated agent
    assert r["decision"] == "allow"


def test_server_module_imports_with_mcp_installed():
    """Sanity check only: the FastMCP wrapper layer imports cleanly
    and the tool functions exist. Not a transport-level integration
    test — that would require spinning up stdio, out of scope here."""
    pytest.importorskip("mcp")
    import importlib

    server = importlib.import_module("agent_dna.mcp_server")
    for name in (
        "pv_decide",
        "pv_report_outcome",
        "pv_verify",
        "pv_lineage",
        "pv_blocked",
        "pv_divergent",
    ):
        assert hasattr(server, name), f"{name} not found on server module"
