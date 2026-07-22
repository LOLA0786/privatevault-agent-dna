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
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Response
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from agent_dna.apikeys import ApiKeyRegistry
from agent_dna.decision import Decision
from agent_dna.runtime import RuntimeMonitor
from agent_dna.trace import AgentAction

DB_PATH = os.environ.get("PV_DB_PATH", "data/privatevault.db")

STATUS_MAP = {
    Decision.ALLOW: 200,
    Decision.REQUIRE_APPROVAL: 202,
    Decision.BLOCK: 403,
}

state: dict[str, Any] = {}


from agent_dna.composition import build_production_runtime  # noqa: E402


def require_api_key(x_api_key: str | None = Header(default=None)):
    """For enforcement endpoints (/v1/decide, /v1/outcome, and every
    other endpoint that exercises or reveals enforcement authority).
    Requires scope="full" explicitly -- an audit-scoped key (the
    credential handed to a third-party auditor) MUST be rejected
    here. verify_scope("full") only matches an entry whose scope is
    literally "full"; it does not accept "audit" for a "full"
    requirement (see ApiKeyRegistry.verify_scope)."""
    reg: ApiKeyRegistry = state.get("apikeys")
    if reg is None or not reg.enabled:
        return "auth-disabled"
    name = reg.verify_scope(x_api_key, required_scope="full")
    if name is None:
        raise HTTPException(status_code=401, detail="invalid or missing API key")
    return name


def require_audit_or_full_key(x_api_key: str | None = Header(default=None)):
    """For read-only audit endpoints (/v1/verify, /v1/audit/export)
    only. Accepts EITHER a full-scope operator key OR an audit-scoped
    key. Full-scope satisfies this because an operator can do
    everything an auditor can; the reverse is enforced by
    require_api_key above, which rejects audit-scoped keys."""
    reg: ApiKeyRegistry = state.get("apikeys")
    if reg is None or not reg.enabled:
        return "auth-disabled"
    name = reg.verify_scope(x_api_key, required_scope="audit")
    if name is None:
        raise HTTPException(
            status_code=401,
            detail="invalid API key, or key scope does not permit audit access",
        )
    return name


@asynccontextmanager
async def lifespan(app: FastAPI):
    # One composition root for every transport (audit Commit set 3):
    # the HTTP API previously constructed scorer+UAAL only, leaving
    # grants/policy/consensus/economics/breaker in the repo but out of
    # the product. build_production_runtime is now the single place
    # the stack is assembled; the connector middleware consumes the
    # same runtime via runtime.middleware().
    runtime = build_production_runtime()
    import sys
    for level, info in runtime.composition.items():
        if info["status"] != "attached":
            print(f"RUNTIME: {level} not attached -- {info['detail']}",
                  file=sys.stderr)
    state["runtime"] = runtime
    state["apikeys"] = runtime.apikeys
    state["store"] = runtime.store
    state["recorder"] = runtime.recorder
    state["engine"] = runtime.engine
    state["signer"] = runtime.signer
    state["monitors"] = {}
    yield
    state["store"].close()
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
    arguments: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)
    request_id: str | None = None


class OutcomeRequest(BaseModel):
    decision_id: str = Field(min_length=1)
    status: str = Field(pattern="^(ok|error|refused)$")
    detail: str = ""


# ---------- enforcement surface ---------------------------------------------

def _enforce_identity(ident: str, agent_id: str) -> None:
    """P0-2: the authenticated credential is the authoritative agent
    identity (same convention as ConnectorMiddleware, which derives
    agent_id from the key). A full key for agent A must not act as
    agent B. In auth-disabled mode (explicit dev-only warning at
    startup) the body value is used as-is."""
    if ident != "auth-disabled" and agent_id != ident:
        raise HTTPException(
            status_code=403,
            detail=f"authenticated identity {ident!r} cannot act as "
                   f"agent {agent_id!r}",
        )


def _owned_decision(ident: str, decision_id: str):
    """Resolve a decision record and enforce ownership. Cross-agent
    access returns the same 404 as an unknown id -- no existence
    oracle across identities."""
    g = state["recorder"].graph
    try:
        record = g.lineage(decision_id)[-1]
    except KeyError:
        raise HTTPException(status_code=404, detail="unknown decision_id") from None
    if ident != "auth-disabled" and record.agent_id != ident:
        raise HTTPException(status_code=404, detail="unknown decision_id")
    return record


@app.post("/v1/decide")
def decide(req: DecideRequest, ident: str = Depends(require_api_key)):
    _enforce_identity(ident, req.agent_id)
    action = AgentAction(
        agent_id=req.agent_id,
        capability=req.capability,
        timestamp=req.timestamp,
        arguments=req.arguments,
        context=req.context,
        request_id=req.request_id,
    )
    monitor = _monitor_for(req.agent_id)
    result = monitor.process(action, evidence=req.evidence or None)
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
def outcome(req: OutcomeRequest, ident: str = Depends(require_api_key)):
    _owned_decision(ident, req.decision_id)
    try:
        event = state["recorder"].report_outcome(
            req.decision_id, req.status, req.detail
        )
    except (KeyError, ValueError) as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    return {"event": event.to_dict()}


@app.get("/v1/runtime", dependencies=[Depends(require_api_key)])
def runtime_composition():
    """The composition manifest: which enforcement levels are attached
    and why the rest are not. Honesty surface -- an operator or
    auditor can see exactly what this deployment enforces."""
    return {"composition": state["runtime"].composition}


# ---------- query surface ----------------------------------------------------

@app.get("/v1/records/{agent_id}")
def records(agent_id: str, ident: str = Depends(require_api_key)):
    if ident != "auth-disabled" and agent_id != ident:
        raise HTTPException(status_code=404, detail="unknown agent_id")
    g = state["recorder"].graph
    return {
        "agent_id": agent_id,
        "records": [r.to_dict() for r in g.find_by_agent(agent_id)],
    }


@app.get("/v1/blocked")
def blocked(ident: str = Depends(require_api_key)):
    g = state["recorder"].graph
    rows = g.find_blocked()
    if ident != "auth-disabled":
        rows = [r for r in rows if r.agent_id == ident]
    return {"blocked": [r.to_dict() for r in rows]}


@app.get("/v1/divergent")
def divergent(ident: str = Depends(require_api_key)):
    g = state["recorder"].graph
    rows = g.find_divergent()
    if ident != "auth-disabled":
        rows = [r for r in rows if r.agent_id == ident]
    return {"divergent": [r.to_dict() for r in rows]}


@app.get("/v1/lineage/{decision_id}")
def lineage(decision_id: str, ident: str = Depends(require_api_key)):
    _owned_decision(ident, decision_id)
    return {
        "lineage": [
            r.to_dict()
            for r in state["recorder"].graph.lineage(decision_id)
        ]
    }


# ---------- audit surface -------------------------------------------------------

@app.get("/v1/envelope/{record_hash}", dependencies=[Depends(require_api_key)])
def envelope(record_hash: str):
    env = state["recorder"].envelopes.get(record_hash)
    if env is None and hasattr(state["store"], "get_envelope"):
        env = state["store"].get_envelope(record_hash)
    if env is None:
        raise HTTPException(
            status_code=404,
            detail="no envelope for this hash (unsigned mode or unknown "
                   "hash; envelopes are persisted transactionally with "
                   "their records and survive restart)",
        )
    return {"envelope": env}


@app.get("/v1/verify", dependencies=[Depends(require_audit_or_full_key)])
def verify():
    return {"chains": state["recorder"].graph.verify_all()}


@app.get("/v1/audit/export", dependencies=[Depends(require_audit_or_full_key)])
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
        "signing": (
            {"algorithm": "Ed25519", "public_key": state["signer"].public_key}
            if state.get("signer") else "disabled"
        ),
        "status": "running",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/metrics")
def prometheus_metrics():
    """Prometheus scrape endpoint.

    Uses prometheus_client when installed; otherwise falls back to a
    minimal text-format exposition built from the decision store so the
    endpoint never 500s (fail-open here is safe: metrics are
    observability, not enforcement).
    """
    try:
        from prometheus_client import (
            CONTENT_TYPE_LATEST,
            generate_latest,
        )
        body = generate_latest()
        content_type = CONTENT_TYPE_LATEST
    except ImportError:
        counts: dict[str, int] = {}
        graph = state.get("graph")
        if graph is not None:
            for rec in getattr(graph, "records", lambda: [])():
                d = getattr(rec, "decision", None)
                key = getattr(d, "value", str(d))
                counts[key] = counts.get(key, 0) + 1
        lines = [
            "# HELP pv_decisions_total Decisions recorded by verdict.",
            "# TYPE pv_decisions_total counter",
        ]
        for verdict, n in sorted(counts.items()):
            lines.append(f'pv_decisions_total{{verdict="{verdict}"}} {n}')
        body = ("\n".join(lines) + "\n").encode()
        content_type = "text/plain; version=0.0.4; charset=utf-8"

    return Response(
        content=body,
        media_type=content_type,
    )
