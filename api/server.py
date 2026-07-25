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
import sys
import tempfile
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Header, HTTPException, Response
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask

from agent_dna.apikeys import ApiKeyRegistry
from agent_dna.decision import Decision
from agent_dna.runtime import RuntimeMonitor
from agent_dna.signer import verify_trusted_envelope
from agent_dna.trace import AgentAction

DB_PATH = os.environ.get("PV_DB_PATH", "data/privatevault.db")

STATUS_MAP = {
    Decision.ALLOW: 200,
    Decision.REQUIRE_APPROVAL: 202,
    Decision.BLOCK: 403,
}

state: dict[str, Any] = {}


@dataclass(frozen=True)
class Principal:
    agent_id: str | None
    scope: str
    authentication_disabled: bool = False

    def owns(self, agent_id: str) -> bool:
        return self.authentication_disabled or self.agent_id == agent_id


AUTH_DISABLED_PRINCIPAL = Principal(
    agent_id=None,
    scope="development",
    authentication_disabled=True,
)


from agent_dna.composition import build_production_runtime  # noqa: E402


def require_api_key(
    x_api_key: str | None = Header(default=None),
) -> Principal:
    """For enforcement endpoints (/v1/decide, /v1/outcome, and every
    other endpoint that exercises or reveals enforcement authority).
    Requires scope="full" explicitly -- an audit-scoped key (the
    credential handed to a third-party auditor) MUST be rejected
    here. verify_scope("full") only matches an entry whose scope is
    literally "full"; it does not accept "audit" for a "full"
    requirement (see ApiKeyRegistry.verify_scope)."""
    reg: ApiKeyRegistry = state.get("apikeys")
    if reg is None or not reg.enabled:
        return AUTH_DISABLED_PRINCIPAL
    name = reg.verify_scope(x_api_key, required_scope="full")
    if name is None:
        raise HTTPException(status_code=401, detail="invalid or missing API key")
    return Principal(agent_id=name, scope="full")


def require_audit_or_full_key(
    x_api_key: str | None = Header(default=None),
) -> Principal:
    """For read-only audit endpoints (/v1/verify, /v1/audit/export)
    only. Accepts EITHER a full-scope operator key OR an audit-scoped
    key. Full-scope satisfies this because an operator can do
    everything an auditor can; the reverse is enforced by
    require_api_key above, which rejects audit-scoped keys."""
    reg: ApiKeyRegistry = state.get("apikeys")
    if reg is None or not reg.enabled:
        return AUTH_DISABLED_PRINCIPAL
    name = reg.verify_scope(x_api_key, required_scope="audit")
    if name is None:
        raise HTTPException(
            status_code=401,
            detail="invalid API key, or key scope does not permit audit access",
        )
    return Principal(agent_id=name, scope="audit")


FullPrincipal = Annotated[Principal, Depends(require_api_key)]


def _assert_auth_configured(auth_enabled: bool) -> None:
    """Fail closed on auth at startup.

    A security runtime must never silently serve enforcement decisions
    with no authentication. Running without keys is permitted ONLY when
    the operator explicitly opts in, so a forgotten PV_API_KEYS_FILE is
    a refused startup rather than an open endpoint -- the same
    fail-closed principle the runtime enforces on agents, applied to
    its own front door.
    """
    if auth_enabled:
        return
    allow = os.getenv("PV_ALLOW_NO_AUTH", "").lower() in ("1", "true", "yes")
    if not allow:
        raise RuntimeError(
            "PrivateVault refuses to start: no API keys configured "
            "(PV_API_KEYS_FILE unset or empty). Configure at least one key, "
            "or set PV_ALLOW_NO_AUTH=1 to run WITHOUT authentication "
            "(development only -- every request runs as its self-declared "
            "identity)."
        )
    print(
        "WARNING: PV_ALLOW_NO_AUTH set -- authentication is DISABLED. "
        "Every request runs as its self-declared identity. Never use this "
        "in production.",
        file=sys.stderr,
    )


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
            print(f"RUNTIME: {level} not attached -- {info['detail']}", file=sys.stderr)
    state["runtime"] = runtime
    state["apikeys"] = runtime.apikeys

    _assert_auth_configured(runtime.apikeys.enabled)
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
    version="0.2.1",
    lifespan=lifespan,
)


def _monitor_for(agent_id: str) -> RuntimeMonitor:
    monitors = state["monitors"]
    if agent_id not in monitors:
        monitors[agent_id] = RuntimeMonitor(state["engine"], recorder=state["recorder"])
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


def _enforce_identity(principal: Principal, agent_id: str) -> None:
    """Require the authenticated credential to own the requested agent."""
    if not principal.owns(agent_id):
        raise HTTPException(
            status_code=403,
            detail=f"authenticated identity {principal.agent_id!r} cannot act as "
            f"agent {agent_id!r}",
        )


def _owned_decision(principal: Principal, decision_id: str):
    """Resolve a decision while preventing cross-agent disclosure."""
    g = state["recorder"].graph
    try:
        record = g.lineage(decision_id)[-1]
    except KeyError:
        raise HTTPException(status_code=404, detail="unknown decision_id") from None
    if not principal.owns(record.agent_id):
        raise HTTPException(status_code=404, detail="unknown decision_id")
    return record


@app.post("/v1/decide")
def decide(req: DecideRequest, principal: FullPrincipal):
    _enforce_identity(principal, req.agent_id)
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
def outcome(req: OutcomeRequest, principal: FullPrincipal):
    _owned_decision(principal, req.decision_id)
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
def records(agent_id: str, principal: FullPrincipal):
    if not principal.owns(agent_id):
        raise HTTPException(status_code=404, detail="unknown agent_id")
    g = state["recorder"].graph
    return {
        "agent_id": agent_id,
        "records": [r.to_dict() for r in g.find_by_agent(agent_id)],
    }


@app.get("/v1/blocked")
def blocked(principal: FullPrincipal):
    g = state["recorder"].graph
    rows = g.find_blocked()
    if not principal.authentication_disabled:
        rows = [r for r in rows if r.agent_id == principal.agent_id]
    return {"blocked": [r.to_dict() for r in rows]}


@app.get("/v1/divergent")
def divergent(principal: FullPrincipal):
    g = state["recorder"].graph
    rows = g.find_divergent()
    if not principal.authentication_disabled:
        rows = [r for r in rows if r.agent_id == principal.agent_id]
    return {"divergent": [r.to_dict() for r in rows]}


@app.get("/v1/lineage/{decision_id}")
def lineage(
    decision_id: str,
    principal: FullPrincipal,
):
    _owned_decision(principal, decision_id)
    return {
        "lineage": [r.to_dict() for r in state["recorder"].graph.lineage(decision_id)]
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


def _verify_runtime_signatures() -> dict[str, object]:
    runtime = state["runtime"]
    trusted_keys = runtime.trusted_public_keys
    records = list(state["store"].iter_decisions())

    result: dict[str, object] = {
        "mode": "trusted" if state.get("signer") is not None else "disabled",
        "trusted_key_count": len(trusted_keys),
        "records_seen": len(records),
        "valid_envelopes": 0,
        "missing_envelopes": 0,
        "invalid_envelopes": 0,
        "verified": None,
    }

    if state.get("signer") is None:
        return result

    valid = 0
    missing = 0
    invalid = 0

    for record in records:
        record_hash = record["record_hash"]
        envelope = state["store"].get_envelope(record_hash)

        if envelope is None:
            missing += 1
        elif verify_trusted_envelope(
            envelope,
            record_hash,
            trusted_keys=trusted_keys,
        ):
            valid += 1
        else:
            invalid += 1

    result.update(
        {
            "valid_envelopes": valid,
            "missing_envelopes": missing,
            "invalid_envelopes": invalid,
            "verified": missing == 0 and invalid == 0,
        }
    )
    return result


@app.get("/v1/verify", dependencies=[Depends(require_audit_or_full_key)])
def verify():
    chains = state["recorder"].graph.verify_all()
    return {
        "chains": chains,
        "chain_integrity_verified": all(chains.values()),
        "signatures": _verify_runtime_signatures(),
    }


def _temporary_export(exporter, filename: str) -> FileResponse:
    fd, tmp_path = tempfile.mkstemp(suffix=".jsonl")
    os.close(fd)
    path = Path(tmp_path)

    try:
        exporter(path)
    except Exception:
        path.unlink(missing_ok=True)
        raise

    return FileResponse(
        path,
        media_type="application/x-ndjson",
        filename=filename,
        background=BackgroundTask(path.unlink, missing_ok=True),
    )


@app.get("/v1/audit/export", dependencies=[Depends(require_audit_or_full_key)])
def audit_export():
    return _temporary_export(
        state["store"].export_jsonl,
        "privatevault_audit.jsonl",
    )


@app.get(
    "/v1/audit/envelopes",
    dependencies=[Depends(require_audit_or_full_key)],
)
def audit_envelope_export():
    return _temporary_export(
        state["store"].export_envelopes_jsonl,
        "privatevault_envelopes.jsonl",
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
            if state.get("signer")
            else "disabled"
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
