"""
PrivateVault Agent DNA — Decision Security API.

POST /v1/decide is the enforcement surface:
  ALLOW            -> 200
  REQUIRE_APPROVAL -> 202
  BLOCK            -> 403
The HTTP status IS the enforcement signal; the body carries the sealed
DecisionRecord. Every decision is persisted (SQLite, WAL) before the
response is returned — no decision without a record.

Audit surface:
  GET /v1/audit/export  -> canonical JSONL (feed to tools/verify_records.py)
  GET /v1/verify        -> in-process chain verification per agent
"""

from __future__ import annotations

import os
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from agent_dna import (
    BehaviorDynamics,
    CapabilityManifold,
    DriftScorer,
)
from agent_dna.adapters import synthetic_normal_trace
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.runtime import RuntimeMonitor
from agent_dna.sqlite_store import SQLiteDecisionStore
from agent_dna.trace import AgentAction

DB_PATH = os.environ.get("PV_DB_PATH", "data/privatevault.db")

STATUS_MAP = {
    Decision.ALLOW: 200,
    Decision.REQUIRE_APPROVAL: 202,
    Decision.BLOCK: 403,
}

state: Dict[str, Any] = {}


def _train_scorer() -> DriftScorer:
    # Synthetic profile until a real trace replaces it — the binding
    # constraint, stated openly in /  (see "calibration").
    training = [synthetic_normal_trace(seed=i, loops=6) for i in range(8)]
    manifold = CapabilityManifold().fit(training)
    dynamics = BehaviorDynamics().fit(training)
    return DriftScorer(manifold, dynamics)


@asynccontextmanager
async def lifespan(app: FastAPI):
    store = SQLiteDecisionStore(DB_PATH)
    recorder = DecisionRecorder(store=store)
    engine = DecisionEngine(scorer=_train_scorer())
    # one monitor per agent_id: behavioral state is per-agent
    state["store"] = store
    state["recorder"] = recorder
    state["engine"] = engine
    state["monitors"] = {}
    yield
    store.close()
    state.clear()


app = FastAPI(
    title="PrivateVault Agent DNA",
    version="0.2.0",
    lifespan=lifespan,
)


def _monitor_for(agent_id: str) -> RuntimeMonitor:
    monitors = state["monitors"]
    if agent_id not in monitors:
        monitors[agent_id] = RuntimeMonitor(
            state["engine"], recorder=state["recorder"]
        )
    return monitors[agent_id]


# ---------- request models -------------------------------------------------

class DecideRequest(BaseModel):
    agent_id: str = Field(min_length=1)
    capability: str = Field(min_length=1)
    timestamp: float
    arguments: Dict[str, Any] = Field(default_factory=dict)
    context: Dict[str, Any] = Field(default_factory=dict)


class OutcomeRequest(BaseModel):
    decision_id: str = Field(min_length=1)
    status: str = Field(pattern="^(ok|error|refused)$")
    detail: str = ""


# ---------- enforcement surface ---------------------------------------------

@app.post("/v1/decide")
def decide(req: DecideRequest):
    action = AgentAction(
        agent_id=req.agent_id,
        capability=req.capability,
        timestamp=req.timestamp,
        arguments=req.arguments,
        context=req.context,
    )
    monitor = _monitor_for(req.agent_id)
    result = monitor.process(action)
    record = list(state["recorder"].graph.find_by_agent(req.agent_id))[-1]

    return JSONResponse(
        status_code=STATUS_MAP[result.decision],
        content={
            "decision": result.decision.value,
            "triggered_by": result.triggered_by,
            "reason": result.reason,
            "record": record.to_dict(),
        },
    )


@app.post("/v1/outcome")
def outcome(req: OutcomeRequest):
    try:
        event = state["recorder"].report_outcome(
            req.decision_id, req.status, req.detail
        )
    except (KeyError, ValueError) as e:
        raise HTTPException(status_code=409, detail=str(e))
    return {"event": event.to_dict()}


# ---------- query surface ----------------------------------------------------

@app.get("/v1/records/{agent_id}")
def records(agent_id: str):
    g = state["recorder"].graph
    return {
        "agent_id": agent_id,
        "records": [r.to_dict() for r in g.find_by_agent(agent_id)],
    }


@app.get("/v1/blocked")
def blocked():
    g = state["recorder"].graph
    return {"blocked": [r.to_dict() for r in g.find_blocked()]}


@app.get("/v1/divergent")
def divergent():
    g = state["recorder"].graph
    return {"divergent": [r.to_dict() for r in g.find_divergent()]}


@app.get("/v1/lineage/{decision_id}")
def lineage(decision_id: str):
    g = state["recorder"].graph
    try:
        path = g.lineage(decision_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="unknown decision_id")
    return {"lineage": [r.to_dict() for r in path]}


# ---------- audit surface -------------------------------------------------------

@app.get("/v1/verify")
def verify():
    return {"chains": state["recorder"].graph.verify_all()}


@app.get("/v1/audit/export")
def audit_export():
    tmp = Path(tempfile.mkstemp(suffix=".jsonl")[1])
    state["store"].export_jsonl(tmp)
    return FileResponse(
        tmp,
        media_type="application/x-ndjson",
        filename="privatevault_audit.jsonl",
    )


# ---------- misc -------------------------------------------------------------------

@app.get("/")
def root():
    return {
        "product": "PrivateVault Agent DNA",
        "category": "Decision Security Runtime",
        "enforcement": "POST /v1/decide (200 allow / 202 approval / 403 block)",
        "calibration": "synthetic behavioral profile — pilot trace pending",
        "status": "running",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}
