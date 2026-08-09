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

import json as _pv_json
import os
import sys
import tempfile
import time as _time
import uuid as _uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC
from datetime import datetime as _datetime
from datetime import timedelta as _timedelta
from pathlib import Path
from typing import Annotated, Any, NoReturn

from fastapi import Depends, FastAPI, Header, HTTPException, Response
from fastapi.responses import FileResponse, JSONResponse
from nacl.signing import SigningKey as _SigningKey
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask

from agent_dna.apikeys import ApiKeyRegistry
from agent_dna.authority_v01 import CANONICALIZATION as _PV_CANON
from agent_dna.authority_v01 import sha256_digest as _pv_sha256_digest
from agent_dna.authorize_binding import (
    AUTHORIZE_DECISION_NOT_FOUND,
    AUTHORIZE_DECISION_REQUIRED,
    bind_authorize_to_sealed_allow,
)
from agent_dna.connector.cross_agent import escalate_with_cross_agent
from agent_dna.decision import Decision
from agent_dna.execution_v01 import EXECUTION_AUTHORIZATION_SPEC as _PV_EA_SPEC
from agent_dna.execution_v01 import sign_execution_authorization as _pv_sign_ea
from agent_dna.observability.logger import get_logger
from agent_dna.observability.metrics import MetricsExporter
from agent_dna.observability.prometheus_bridge import (
    generate_latest as _prom_generate_latest,
)
from agent_dna.observability.prometheus_bridge import observe_decide_latency, set_ready
from agent_dna.runtime import RuntimeMonitor
from agent_dna.security.loop_discovery import (
    LoopDecision,
    LoopFormatError,
    discover_loops,
)
from agent_dna.signer import verify_trusted_envelope
from agent_dna.trace import AgentAction

_log = get_logger("pv.api")

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
    reg = state.get("apikeys")
    if not isinstance(reg, ApiKeyRegistry) or not reg.enabled:
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
    reg = state.get("apikeys")
    if not isinstance(reg, ApiKeyRegistry) or not reg.enabled:
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
    state["cross_agent"] = runtime.cross_agent
    state["monitors"] = {}
    state["started_at"] = _datetime.now(UTC).isoformat()
    try:
        runtime.store.ping()
        set_ready(True)
    except Exception as exc:
        set_ready(False)
        raise RuntimeError(f"store not ready at startup: {exc}") from exc
    _log.info(
        f"runtime_ready auth_enabled={runtime.apikeys.enabled} "
        f"db={getattr(runtime.store, 'path', '')}",
    )
    yield
    set_ready(False)
    state["store"].close()
    state.clear()


app = FastAPI(
    title="PrivateVault Agent DNA",
    version="0.4.0",
    lifespan=lifespan,
)


def _monitor_for(agent_id: str) -> RuntimeMonitor:
    """Per-agent monitor without an attached recorder.

    Recording happens after CABI escalate so the sealed DecisionRecord
    matches the final verdict (same convention as ConnectorMiddleware).
    """
    monitors = state["monitors"]
    if agent_id not in monitors:
        monitors[agent_id] = RuntimeMonitor(state["engine"], recorder=None)
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
    # Convenience alias; also accepted via context.execution_id
    execution_id: str | None = None


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
    context = dict(req.context or {})
    execution_id = req.execution_id or context.get("execution_id")
    if execution_id:
        context["execution_id"] = execution_id
    action = AgentAction(
        agent_id=req.agent_id,
        capability=req.capability,
        timestamp=req.timestamp,
        arguments=req.arguments,
        context=context,
        request_id=req.request_id,
    )
    monitor = _monitor_for(req.agent_id)
    started = _time.perf_counter()
    result = monitor.process(action, evidence=req.evidence or None)
    result = escalate_with_cross_agent(
        state.get("cross_agent"),
        execution_id=execution_id,
        agent_id=req.agent_id,
        capability=req.capability,
        result=result,
    )
    observe_decide_latency(_time.perf_counter() - started)
    record = state["recorder"].record(action, result)

    return JSONResponse(
        status_code=STATUS_MAP[result.decision],
        content={
            "decision": result.decision.value,
            "triggered_by": result.triggered_by,
            "reason": result.reason,
            "execution_id": execution_id,
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
        "category": "Decision Security Platform",
        "deployment": "single-tenant self-hosted",
        "enforcement": "POST /v1/decide (200 allow / 202 approval / 403 block)",
        "ops": {
            "health": "GET /health",
            "ready": "GET /ready",
            "metrics": "GET /metrics",
            "summary": "GET /v1/ops/summary",
            "console": "operator dashboard (compose profile: platform)",
        },
        "calibration": "synthetic behavioral profile — pilot trace pending",
        "certification": "none — see docs/WHAT-WE-DO-NOT-CLAIM.md",
        "signing": (
            {"algorithm": "Ed25519", "public_key": state["signer"].public_key}
            if state.get("signer")
            else "disabled"
        ),
        "status": "running",
        "started_at": state.get("started_at"),
    }


@app.get("/health")
def health():
    """Liveness: process is up. Prefer /ready for orchestration gates."""
    return {"status": "healthy"}


@app.get("/ready")
def ready():
    """Readiness: store accepts queries and auth posture is known."""
    store = state.get("store")
    if store is None:
        set_ready(False)
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "reason": "store_uninitialized"},
        )
    try:
        store.ping()
    except Exception as exc:
        set_ready(False)
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "reason": "store_unavailable",
                "detail": str(exc),
            },
        )
    set_ready(True)
    reg = state.get("apikeys")
    auth_enabled = isinstance(reg, ApiKeyRegistry) and reg.enabled
    return {
        "status": "ready",
        "auth_enabled": auth_enabled,
        "signing_enabled": state.get("signer") is not None,
        "db_path": str(getattr(store, "path", "")),
        "started_at": state.get("started_at"),
    }


def _aggregate_monitor_metrics() -> dict[str, Any]:
    merged = MetricsExporter()
    for monitor in state.get("monitors", {}).values():
        metrics = getattr(monitor, "metrics", None)
        if isinstance(metrics, MetricsExporter):
            merged.merge(metrics)
    return merged.summary()


@app.get("/v1/ops/summary", dependencies=[Depends(require_audit_or_full_key)])
def ops_summary():
    """Operator-facing JSON metrics (audit or full scope)."""
    summary = _aggregate_monitor_metrics()
    return {
        "product": "PrivateVault Agent DNA",
        "ready": True,
        "auth_enabled": isinstance(state.get("apikeys"), ApiKeyRegistry)
        and state["apikeys"].enabled,
        "agents_monitored": len(state.get("monitors", {})),
        "metrics": summary,
        "started_at": state.get("started_at"),
    }


@app.get("/metrics")
def prometheus_metrics():
    """Prometheus scrape endpoint.

    Prefer prometheus_client counters wired from RuntimeMonitor; fall back to
    in-process monitor aggregates so the endpoint never 500s. Metrics never
    authorize.
    """
    generated = _prom_generate_latest()
    if generated is not None:
        body, content_type = generated
        return Response(content=body, media_type=content_type)

    summary = _aggregate_monitor_metrics()
    lines = [
        "# HELP pv_decisions_total Decisions recorded by verdict.",
        "# TYPE pv_decisions_total counter",
    ]
    for verdict, n in sorted(summary.get("verdict_distribution", {}).items()):
        safe = str(verdict).replace('"', "")
        lines.append(f'pv_decisions_total{{verdict="{safe}"}} {int(n)}')
    lines.extend(
        [
            "# HELP pv_ready 1 when the process reports ready.",
            "# TYPE pv_ready gauge",
            f"pv_ready {1 if state.get('store') is not None else 0}",
        ]
    )
    body = ("\n".join(lines) + "\n").encode()
    return Response(
        content=body,
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


# --------------------------------------------------------------------------
# /v1/authorize - mint a signed, single-use execution authorization.
#
# This is the bridge between an ALLOW and a permitted dispatch. It takes the
# wire-byte DIGEST, never the bytes, so payloads stay out of the control
# plane; the permit still binds exact bytes because the digest is a signed
# field the dispatch boundary recomputes.
# --------------------------------------------------------------------------
_PV_DIGEST = r"^sha256:[0-9a-f]{64}$"
_pv_signer_cache: dict[str, Any] = {}


class AuthorizeRequest(BaseModel):
    request_id: str = Field(min_length=1)
    agent_id: str = Field(min_length=1)
    organisation_id: str = Field(min_length=1)

    # Required reference to a sealed decision — at least one must be set.
    # There is no flag that disables this binding.
    decision_id: str | None = Field(default=None, min_length=1)
    record_hash: str | None = Field(default=None, min_length=1)

    action: dict[str, Any]
    dispatch: dict[str, Any]

    expected_wire_bytes_digest: str = Field(pattern=_PV_DIGEST)
    expected_wire_bytes_length: int = Field(ge=0)
    expected_peer_identity_digest: str = Field(pattern=_PV_DIGEST)

    decision_receipt_digest: str = Field(pattern=_PV_DIGEST)
    authority_receipt_digest: str = Field(pattern=_PV_DIGEST)
    approval_artifact_digest: str | None = Field(default=None, pattern=_PV_DIGEST)
    state_snapshot_digest: str = Field(pattern=_PV_DIGEST)
    policy_bundle_digest: str = Field(pattern=_PV_DIGEST)
    obligations_digest: str = Field(pattern=_PV_DIGEST)
    # Multi-agent authority boundary: when supplied, discover_loops must ALLOW
    security_events: list[dict[str, Any]] | None = None


def _pv_load_signer() -> dict[str, Any]:
    if _pv_signer_cache:
        return _pv_signer_cache

    key_path = os.environ.get("PV_EXECUTION_SIGNER_KEY", "")
    bundle_path = os.environ.get("PV_TRUST_BUNDLE", "")

    if not key_path or not bundle_path:
        raise HTTPException(
            status_code=503,
            detail="execution authorization signer is not configured",
        )

    try:
        signing_key = _SigningKey(Path(key_path).read_bytes())
        trust_bundle = _pv_json.loads(Path(bundle_path).read_text())
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise HTTPException(
            status_code=503,
            detail=f"signer material unreadable: {type(exc).__name__}",
        ) from exc

    _pv_signer_cache["signing_key"] = signing_key
    _pv_signer_cache["trust_bundle"] = trust_bundle
    _pv_signer_cache["key_id"] = trust_bundle["keys"][0]["key_id"]
    return _pv_signer_cache


def _pv_rfc3339(moment: _datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _authorize_refusal(status_code: int, reason_code: str, detail: str) -> NoReturn:
    raise HTTPException(
        status_code=status_code,
        detail={"reason_code": reason_code, "detail": detail},
    )


def _require_sealed_allow_for_authorize(req: AuthorizeRequest) -> dict[str, Any]:
    """Load and bind a sealed ALLOW; refuse with distinct reason codes."""
    if not req.decision_id and not req.record_hash:
        _authorize_refusal(
            422,
            AUTHORIZE_DECISION_REQUIRED,
            "decision_id and/or record_hash is required to mint",
        )

    store = state.get("store")
    if store is None or not hasattr(store, "get_decision"):
        raise HTTPException(
            status_code=503,
            detail="decision store is not available for authorize binding",
        )

    record: dict[str, Any] | None = None
    if req.decision_id:
        record = store.get_decision(req.decision_id)
    elif req.record_hash:
        record = store.get_decision_by_record_hash(req.record_hash)

    if record is None:
        _authorize_refusal(
            404,
            AUTHORIZE_DECISION_NOT_FOUND,
            "no sealed decision matches the supplied reference",
        )

    bind_reason = bind_authorize_to_sealed_allow(
        record,
        agent_id=req.agent_id,
        decision_receipt_digest=req.decision_receipt_digest,
        action=req.action,
        record_hash=req.record_hash,
    )
    if bind_reason is not None:
        status = 404 if bind_reason == AUTHORIZE_DECISION_NOT_FOUND else 403
        _authorize_refusal(
            status,
            bind_reason,
            "authorize mint refused: sealed ALLOW binding failed",
        )
    return record


def _authorize_loop_gate(
    security_events: list[dict[str, Any]],
) -> dict[str, Any]:
    try:
        report = discover_loops(security_events)
    except LoopFormatError as exc:
        raise HTTPException(
            status_code=422,
            detail=f"security_events rejected: {exc}",
        ) from exc
    loop_report = report.to_dict()
    if report.decision is not LoopDecision.ALLOW:
        raise HTTPException(
            status_code=403,
            detail={
                "triggered_by": "loop_discovery",
                "decision": report.decision.value,
                "report_id": report.report_id,
                "input_digest": report.input_digest,
                "findings": loop_report.get("findings", []),
            },
        )
    return loop_report


@app.post("/v1/authorize")
def authorize(req: AuthorizeRequest, principal: FullPrincipal):
    """Issue execution authority bound to a sealed ALLOW and exact bytes."""

    _enforce_identity(principal, req.agent_id)
    _require_sealed_allow_for_authorize(req)

    signer = _pv_load_signer()
    trust_bundle = signer["trust_bundle"]

    if req.organisation_id != trust_bundle["organisation_id"]:
        raise HTTPException(
            status_code=403,
            detail="organisation does not match the pinned trust bundle",
        )

    loop_report: dict[str, Any] | None = None
    if req.security_events is not None:
        loop_report = _authorize_loop_gate(req.security_events)

    ttl = int(os.environ.get("PV_AUTHORIZATION_TTL_SECONDS", "60"))
    now = _datetime.now(UTC)

    unsigned = {
        "spec": _PV_EA_SPEC,
        "canonicalization": _PV_CANON,
        "execution_authorization_id": f"eauth-{_uuid.uuid4()}",
        "organisation_id": req.organisation_id,
        "request_id": req.request_id,
        "issued_at": _pv_rfc3339(now),
        "not_before": _pv_rfc3339(now),
        "expires_at": _pv_rfc3339(now + _timedelta(seconds=ttl)),
        "nonce": _uuid.uuid4().hex,
        "decision_receipt_digest": req.decision_receipt_digest,
        "authority_receipt_digest": req.authority_receipt_digest,
        "approval_artifact_digest": req.approval_artifact_digest,
        "action": req.action,
        "action_digest": _pv_sha256_digest(req.action),
        "expected_wire_bytes_digest": req.expected_wire_bytes_digest,
        "expected_wire_bytes_length": req.expected_wire_bytes_length,
        "expected_peer_identity_digest": req.expected_peer_identity_digest,
        "dispatch": req.dispatch,
        "state_snapshot_digest": req.state_snapshot_digest,
        "policy_bundle_digest": req.policy_bundle_digest,
        "trust_bundle_digest": _pv_sha256_digest(trust_bundle),
        "obligations_digest": req.obligations_digest,
        "max_uses": 1,
        "signer_key_id": signer["key_id"],
    }

    try:
        authorization = _pv_sign_ea(unsigned, signer["signing_key"])
    except Exception as exc:
        # A malformed permit fails here, not in front of an auditor.
        raise HTTPException(
            status_code=422,
            detail=f"execution authorization rejected: {type(exc).__name__}",
        ) from exc

    body: dict[str, Any] = {
        "authorization": authorization,
        "trust_bundle": trust_bundle,
        "at_time": _pv_rfc3339(now),
    }
    if loop_report is not None:
        # Report retained beside the mint; adapters must persist both.
        body["loop_discovery"] = {
            "decision": loop_report["decision"],
            "report_id": loop_report["report_id"],
            "input_digest": loop_report["input_digest"],
        }
    return body
