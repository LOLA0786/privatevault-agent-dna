"""
MCP server exposing the composed decision line as tools.

Run standalone: python -m agent_dna.mcp_server
Requires: pip install mcp

Tools:
  pv_decide          - submit an action for pre-execution enforcement
  pv_report_outcome  - report what actually executed (hash-anchored)
  pv_verify          - verify per-agent hash chain integrity
  pv_lineage         - full decision lineage for a decision_id
  pv_blocked         - all BLOCK decisions
  pv_divergent       - enforcement divergences (BLOCK that executed anyway)

Calibration note: the default scorer here is trained on synthetic
traces, same as api/server.py — stated explicitly, not hidden.
"""

from __future__ import annotations

import os
from typing import Any

from mcp.server.fastmcp import FastMCP

from .adapters import synthetic_normal_trace
from .decision import DecisionEngine
from .decision_recorder import DecisionRecorder
from .dynamics import BehaviorDynamics
from .manifold import CapabilityManifold
from .mcp_gateway import MCPGateway
from .scorer import DriftScorer
from .sqlite_store import SQLiteDecisionStore

DB_PATH = os.environ.get("PV_DB_PATH", "data/privatevault_mcp.db")


def _train_scorer() -> DriftScorer:
    training = [synthetic_normal_trace(seed=i, loops=6) for i in range(8)]
    manifold = CapabilityManifold().fit(training)
    dynamics = BehaviorDynamics().fit(training)
    return DriftScorer(manifold, dynamics)


store = SQLiteDecisionStore(DB_PATH)
recorder = DecisionRecorder(store=store)
engine = DecisionEngine(scorer=_train_scorer())
gateway = MCPGateway(engine, recorder)

mcp = FastMCP("privatevault-decision-security")


@mcp.tool()
def pv_decide(
    agent_id: str,
    capability: str,
    arguments: dict[str, Any] | None = None,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Submit an agent action for pre-execution enforcement. Returns
    decision (allow/require_approval/block), triggered_by (which
    precedence level decided), and a decision_id/record_hash for
    later outcome reporting and lineage queries."""
    return gateway.decide(agent_id, capability, arguments, evidence)


@mcp.tool()
def pv_report_outcome(
    decision_id: str, status: str, detail: str = ""
) -> dict[str, Any]:
    """Report what actually executed for a prior decision. status
    must be one of: ok, error, refused. Anchored to the decision's
    hash; at most one report per decision_id."""
    return gateway.report_outcome(decision_id, status, detail)


@mcp.tool()
def pv_verify() -> dict[str, bool]:
    """Verify hash-chain integrity per agent. True means the chain
    is intact and unmodified."""
    return gateway.verify()


@mcp.tool()
def pv_lineage(decision_id: str) -> list[dict[str, Any]]:
    """Full root-to-node decision lineage for a given decision_id."""
    return gateway.lineage(decision_id)


@mcp.tool()
def pv_blocked() -> list[dict[str, Any]]:
    """All decisions with verdict BLOCK, across all agents."""
    return gateway.blocked()


@mcp.tool()
def pv_divergent() -> list[dict[str, Any]]:
    """Enforcement divergences: decisions that were BLOCK but whose
    reported outcome was 'ok' — the runtime said no and the world
    executed anyway."""
    return gateway.divergent()


if __name__ == "__main__":
    mcp.run()
