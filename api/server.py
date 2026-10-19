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

import hashlib
import json as _pv_json
import os
import sqlite3
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
from typing import Annotated, Any, NoReturn, cast

from fastapi import Depends, FastAPI, Header, HTTPException, Response
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.background import BackgroundTask

from agent_dna.apikeys import ApiKeyRegistry
from agent_dna.approval_bridge import (
    APPROVAL_NOT_CONFIGURED,
    APPROVAL_REQUIRES_BOUND_DECISION,
    TRIGGERED_BY_APPROVAL,
    ApprovalContext,
)
from agent_dna.authority_deadline import (
    DECISION_MINT_WINDOW_SECONDS_DEFAULT,
    DECISION_MINT_WINDOW_SECONDS_MAX,
    DECISION_MINT_WINDOW_SECONDS_MIN,
    AuthorityDeadline,
    AuthorityUnknownError,
    authority_deadline,
)
from agent_dna.authority_v01 import CANONICALIZATION as _PV_CANON
from agent_dna.authority_v01 import MAX_JSON_NESTING_DEPTH
from agent_dna.authority_v01 import encode_public_key as _pv_encode_public_key
from agent_dna.authority_v01 import sha256_digest as _pv_sha256_digest
from agent_dna.authorize_binding import (
    AUTHORIZE_APPROVAL_MISMATCH,
    AUTHORIZE_AUTHORITY_EXPIRED,
    AUTHORIZE_AUTHORITY_UNKNOWN,
    AUTHORIZE_DECISION_NOT_FOUND,
    AUTHORIZE_DECISION_REQUIRED,
    AUTHORIZE_EVIDENCE_MISMATCH,
    AUTHORIZE_EVIDENCE_REQUIRED,
    AUTHORIZE_EVIDENCE_UNKNOWN,
    AUTHORIZE_GRANT_REVOKED,
    AUTHORIZE_OPERATION_MISMATCH,
    AUTHORIZE_OPERATION_NOT_DECLARED,
    AUTHORIZE_OPERATIONS_REQUIRED,
    AUTHORIZE_PERMIT_ALREADY_CONSUMED,
    AUTHORIZE_PERMIT_BINDING_CONFLICT,
    AUTHORIZE_PERMIT_EXPIRED,
    AUTHORIZE_PERMIT_INDETERMINATE,
    AUTHORIZE_PERMIT_TRUST_BUNDLE_DIGEST_MISMATCH,
    AUTHORIZE_PERMIT_TRUST_BUNDLE_MISSING,
    AUTHORIZE_POLICY_CHANGED,
    AUTHORIZE_PRESENTER_NOT_PINNED,
    AUTHORIZE_PRESENTER_REQUIRED,
    AUTHORIZE_PRESENTER_UNCONFIGURED,
    AUTHORIZE_SIGNER_UNAVAILABLE,
    AUTHORIZE_STORE_UNAVAILABLE,
    bind_authorize_to_sealed_allow,
    mint_bindings_digest,
)
from agent_dna.connector.cross_agent import escalate_with_cross_agent
from agent_dna.control_posture import (
    AUTHORIZE_LOOP_EVENTS_REQUIRED,
    attach_control_posture,
    authorization_mode_of,
)
from agent_dna.decision import Decision, DecisionResult
from agent_dna.decision_graph import DecisionGraph
from agent_dna.execution_v01 import EXECUTION_AUTHORIZATION_SPEC as _PV_EA_SPEC
from agent_dna.execution_v01 import (
    EXECUTION_AUTHORIZATION_SPEC_V02 as _PV_EA_SPEC_V02,
)
from agent_dna.execution_v01 import sign_execution_authorization as _pv_sign_ea
from agent_dna.key_custody import SignerError, is_kms_ref, signer_from_seed_file
from agent_dna.lineage import (
    ALREADY_APPROVED as LINEAGE_ALREADY_APPROVED,
)
from agent_dna.lineage import (
    LINEAGE_EVENT_SPEC,
    LineageFinding,
    LineageLedger,
    escalate_with_lineage,
    lineage_manifest,
    lineage_mode,
)
from agent_dna.observability.logger import get_logger
from agent_dna.observability.metrics import MetricsExporter
from agent_dna.observability.prometheus_bridge import (
    generate_latest as _prom_generate_latest,
)
from agent_dna.observability.prometheus_bridge import observe_decide_latency, set_ready
from agent_dna.operation_registry import (
    OPERATION_NOT_DECLARED,
    OperationRegistry,
    OperationRegistryError,
    load_operation_registry,
    operation_block,
)
from agent_dna.permit_evidence import (
    PERMIT_EVIDENCE_KEY,
    SERVER,
    PermitEvidenceError,
    decided_evidence,
    evidence_mode,
    first_mismatch,
    policy_bundle_digest,
    sealed_evidence,
)
from agent_dna.presenter_identity import (
    PresenterBundle,
    PresenterIdentityError,
    load_presenter_bundle,
)
from agent_dna.request_bounds import RequestBounds, RequestBoundsMiddleware
from agent_dna.revocation_list import build_revocation_list
from agent_dna.runtime import RuntimeMonitor
from agent_dna.security.loop_discovery import (
    LoopDecision,
    LoopFormatError,
    LoopPolicy,
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
    credential_fingerprint: str = ""

    def owns(self, agent_id: str) -> bool:
        return self.authentication_disabled or self.agent_id == agent_id


AUTH_DISABLED_PRINCIPAL = Principal(
    agent_id=None,
    scope="development",
    authentication_disabled=True,
    credential_fingerprint="disabled",
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
    fingerprint = hashlib.sha256((x_api_key or "").encode("utf-8")).hexdigest()
    return Principal(agent_id=name, scope="full", credential_fingerprint=fingerprint)


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
        "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n"
        "UNSAFE: PV_ALLOW_NO_AUTH=1 — authentication is DISABLED.\n"
        "Every request runs as its self-declared identity.\n"
        "Never use this in production. Prefer PV_SECURE_PROFILE=1.\n"
        "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
        file=sys.stderr,
    )


AUTHORIZATION_TTL_SECONDS_DEFAULT = 60
AUTHORIZATION_TTL_SECONDS_MIN = 1
AUTHORIZATION_TTL_SECONDS_MAX = 300
AUTHORIZATION_NOT_BEFORE_LEEWAY_SECONDS_MAX = 30


@dataclass(frozen=True)
class AuthorizationWindow:
    """How long a minted permit lives, and how far back ``not_before`` sits.

    Validated once at startup (R1 #5). The sidecar judges the window
    strictly by its own clock, so ``not_before_leeway_seconds`` is the one
    sanctioned place to absorb a small clock difference between the mint
    host and the dispatching host. It never moves ``expires_at``.
    """

    ttl_seconds: int
    not_before_leeway_seconds: int
    # How long after a decision its ALLOW may still be minted (finding 2 of
    # the 19 October 2026 review). Approval and grant expiry cap it further.
    decision_window_seconds: int = DECISION_MINT_WINDOW_SECONDS_DEFAULT


def _env_int_bounded(
    env: Any, name: str, default: int, minimum: int, maximum: int
) -> int:
    raw = str(env.get(name, "") or "").strip()
    if raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise RuntimeError(
            f"{name} must be an integer between {minimum} and {maximum}; got {raw!r}"
        ) from None
    if not minimum <= value <= maximum:
        raise RuntimeError(
            f"{name} must be between {minimum} and {maximum}; got {value}"
        )
    return value


def _authorization_window(env: Any = None) -> AuthorizationWindow:
    """Parse and bound the mint window. Raises RuntimeError on misconfiguration
    so the server refuses to start rather than failing every authorize."""
    source = os.environ if env is None else env
    return AuthorizationWindow(
        ttl_seconds=_env_int_bounded(
            source,
            "PV_AUTHORIZATION_TTL_SECONDS",
            AUTHORIZATION_TTL_SECONDS_DEFAULT,
            AUTHORIZATION_TTL_SECONDS_MIN,
            AUTHORIZATION_TTL_SECONDS_MAX,
        ),
        not_before_leeway_seconds=_env_int_bounded(
            source,
            "PV_AUTHORIZATION_NOT_BEFORE_LEEWAY_SECONDS",
            0,
            0,
            AUTHORIZATION_NOT_BEFORE_LEEWAY_SECONDS_MAX,
        ),
        decision_window_seconds=_env_int_bounded(
            source,
            "PV_DECISION_MINT_WINDOW_SECONDS",
            DECISION_MINT_WINDOW_SECONDS_DEFAULT,
            DECISION_MINT_WINDOW_SECONDS_MIN,
            DECISION_MINT_WINDOW_SECONDS_MAX,
        ),
    )


def _presenter_bundle(env: Any = None) -> PresenterBundle | None:
    """PV_PRESENTER_BUNDLE: operator-pinned TLS presenters per agent (ADR
    0022). A configured bundle that cannot be read stops start-up: serving
    without it would mint permits any process could present."""
    source = os.environ if env is None else env
    path = source.get("PV_PRESENTER_BUNDLE", "")
    if not path:
        return None
    try:
        return load_presenter_bundle(path)
    except PresenterIdentityError as exc:
        raise RuntimeError(f"PV_PRESENTER_BUNDLE: {exc}") from exc


def _presenter_manifest(bundle: PresenterBundle | None) -> dict[str, str]:
    if bundle is None:
        return {
            "status": "not_configured",
            "detail": "PV_PRESENTER_BUNDLE unset: permits do not name who may "
            "present them (spec 0.1); receivers cannot authenticate the presenter",
        }
    return {
        "status": "attached",
        "detail": f"every permit binds a pinned TLS client key "
        f"({len(bundle.presenters)} agent(s), bundle {bundle.digest[:19]}); "
        "spec 0.2",
    }


def _operation_registry(env: Any = None) -> OperationRegistry | None:
    """PV_OPERATIONS_FILE (ADR 0025): the operations each capability may
    perform. A configured file that cannot be read stops start-up."""
    source = os.environ if env is None else env
    path = source.get("PV_OPERATIONS_FILE", "")
    if not path:
        return None
    try:
        return load_operation_registry(path)
    except OperationRegistryError as exc:
        raise RuntimeError(f"PV_OPERATIONS_FILE: {exc}") from exc


def _secure_profile_on(env: Any = None) -> bool:
    source = os.environ if env is None else env
    return str(source.get("PV_SECURE_PROFILE", "0")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _operations_manifest(
    registry: OperationRegistry | None, secure: bool
) -> dict[str, str]:
    if registry is None:
        return {
            "status": "not_configured",
            "detail": (
                "PV_OPERATIONS_FILE unset under the secure profile: every mint is refused"
                if secure
                else "PV_OPERATIONS_FILE unset: a capability is not bound to the "
                "operations it may perform (ADR 0025); constrain them with policy"
            ),
        }
    return {
        "status": "attached",
        "detail": f"{registry.size} declared operation(s); a bound request must "
        f"match one for its capability (registry {registry.digest})",
    }


def _permit_evidence(
    registry: OperationRegistry | None, env: Any = None
) -> dict[str, str]:
    """ADR 0026: where a permit's four evidence references come from, and
    the digest of the decision configuration this server loaded."""
    source = os.environ if env is None else env
    try:
        return {
            "mode": evidence_mode(source, secure=_secure_profile_on(source)),
            "policy_bundle_digest": policy_bundle_digest(
                source,
                operations_digest=registry.digest if registry is not None else None,
            ),
        }
    except PermitEvidenceError as exc:
        raise RuntimeError(str(exc)) from exc


def _permit_evidence_manifest(evidence: dict[str, str]) -> dict[str, str]:
    if evidence["mode"] == SERVER:
        return {
            "status": "attached",
            "mode": SERVER,
            "policy_bundle_digest": evidence["policy_bundle_digest"],
            "detail": "permits cite the policy bundle and grant sealed at decide "
            "time; state snapshot and obligations are the all-zero digest "
            "(not evaluated); a caller value that differs is refused (ADR 0026)",
        }
    return {
        "status": "not_configured",
        "mode": "caller",
        "policy_bundle_digest": evidence["policy_bundle_digest"],
        "detail": "PV_PERMIT_EVIDENCE=caller: a policy, authority receipt, "
        "state snapshot or obligations digest the caller sends is signed as "
        "the caller's assertion, not checked by this server; omitted ones are "
        "the values sealed at decide time (ADR 0026)",
    }


MAX_REQUEST_BYTES_DEFAULT = 1_048_576
MAX_REQUEST_BYTES_MIN = 1024
MAX_REQUEST_BYTES_MAX = 64 * 1_048_576


def _request_bounds(env: Any = None) -> RequestBounds:
    """Body size and JSON nesting limits, validated once at startup (R1 #7)."""
    source = os.environ if env is None else env
    return RequestBounds(
        max_bytes=_env_int_bounded(
            source,
            "PV_MAX_REQUEST_BYTES",
            MAX_REQUEST_BYTES_DEFAULT,
            MAX_REQUEST_BYTES_MIN,
            MAX_REQUEST_BYTES_MAX,
        ),
        max_json_depth=MAX_JSON_NESTING_DEPTH,
    )


def _assert_secure_authorize_material() -> None:
    """Under PV_SECURE_PROFILE, refuse to start without mint material."""
    secure = os.getenv("PV_SECURE_PROFILE", "").lower() in (
        "1",
        "true",
        "yes",
        "on",
    )
    if not secure:
        return
    key = os.getenv("PV_EXECUTION_SIGNER_KEY")
    bundle = os.getenv("PV_TRUST_BUNDLE")
    missing = [
        name
        for name, value in (
            ("PV_EXECUTION_SIGNER_KEY", key),
            ("PV_TRUST_BUNDLE", bundle),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(
            "PV_SECURE_PROFILE=1 requires execution mint material: "
            + ", ".join(missing)
            + " (see tools/init_execution_signer.py)"
        )
    for label, path in (
        ("PV_EXECUTION_SIGNER_KEY", key),
        ("PV_TRUST_BUNDLE", bundle),
    ):
        if path is not None and not is_kms_ref(path) and not Path(path).is_file():
            raise RuntimeError(f"{label} path does not exist: {path}")


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
    if runtime.composition.get("authorization", {}).get("mode") == "open":
        print(
            "UNSAFE: authorization mode=open (PV_ALLOW_NO_AUTH). "
            "Capability default-deny is OFF.",
            file=sys.stderr,
        )
    state["runtime"] = runtime
    state["apikeys"] = runtime.apikeys

    _assert_auth_configured(runtime.apikeys.enabled)
    _assert_secure_authorize_material()
    state["authorization_window"] = _authorization_window()
    state["presenter_bundle"] = _presenter_bundle()
    state["operation_registry"] = _operation_registry()
    runtime.composition["operation_registry"] = _operations_manifest(
        state["operation_registry"], _secure_profile_on()
    )
    state["permit_evidence"] = _permit_evidence(state["operation_registry"])
    runtime.composition["permit_evidence"] = _permit_evidence_manifest(
        state["permit_evidence"]
    )
    runtime.composition["presenter_binding"] = _presenter_manifest(
        state["presenter_bundle"]
    )
    state["request_bounds"] = _request_bounds()
    state["store"] = runtime.store
    state["recorder"] = runtime.recorder
    state["engine"] = runtime.engine
    state["signer"] = runtime.signer
    state["cross_agent"] = runtime.cross_agent
    state["lineage_mode"] = lineage_mode()
    lineage_db = runtime.lineage_db or getattr(runtime.store, "path", None)
    state["lineage"] = (
        LineageLedger(lineage_db, signer=runtime.signer)
        if state["lineage_mode"] != "off" and lineage_db is not None
        else None
    )
    runtime.composition["lineage"] = lineage_manifest(
        state["lineage_mode"], state["lineage"] is not None
    )
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
    if state.get("lineage") is not None:
        state["lineage"].close()
    state["store"].close()
    state.clear()


app = FastAPI(
    title="PrivateVault Agent DNA",
    version="0.4.0",
    lifespan=lifespan,
)
# Outermost: oversize or over-nested bodies never reach routing, auth, or
# the JSON parser. Limits are read from state once the lifespan validated them.
app.add_middleware(RequestBoundsMiddleware, bounds=lambda: state.get("request_bounds"))


_MONITOR_EVENTS = 256


def _monitor_for(agent_id: str) -> RuntimeMonitor:
    """Per-agent monitor without an attached recorder.

    Recording happens after CABI escalate so the sealed DecisionRecord
    matches the final verdict (same convention as ConnectorMiddleware).
    """
    monitors = state["monitors"]
    if agent_id not in monitors:
        baselines = state["runtime"].agent_baselines
        monitors[agent_id] = RuntimeMonitor(
            state["engine"],
            recorder=None,
            # PostgreSQL: one baseline per agent across every instance.
            state=baselines.for_agent(agent_id) if baselines is not None else None,
            # Decisions are recorded in the store; this history is only for
            # metrics and must not grow with every request.
            max_events=_MONITOR_EVENTS,
        )
    return monitors[agent_id]


# ---------- request models -------------------------------------------------


class LineageRef(BaseModel):
    """ADR 0021: link this decide to decisions the server already sealed.

    Never a caller-chosen flow id: only references to recorded decisions,
    which the server resolves from its own lineage rows.
    """

    model_config = ConfigDict(extra="forbid")
    parent_record_hash: str | None = Field(
        default=None, pattern=r"^(sha256:)?[0-9a-f]{64}$"
    )
    approves: str | None = Field(default=None, pattern=r"^(sha256:)?[0-9a-f]{64}$")


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
    # Supply both for a mintable DRP 0.2 record. Omit both for an
    # audit-only DRP 0.1 record, which cannot mint a permit. Digests are
    # derived server-side; callers must not supply action_digest or
    # dispatch_context_digest.
    execution_action: dict[str, Any] | None = None
    dispatch_context: dict[str, Any] | None = None
    # ADR 0020: a signed human approval for exactly this execution action
    # (approval_v01 request, artifact, approver_authority_receipt). Only
    # meaningful on a mintable decide; refused outright when no approver
    # trust bundle is pinned.
    approval: dict[str, Any] | None = None
    # Optional first-request wire binding. When supplied with a mintable
    # decide, these must equal the named serialization of
    # execution_action.parameters — otherwise decide refuses rather than
    # sealing an inconsistent pair.
    expected_wire_bytes_digest: str | None = Field(
        default=None, pattern=r"^sha256:[0-9a-f]{64}$"
    )
    expected_wire_bytes_length: int | None = Field(default=None, ge=0)
    # ADR 0021 server-derived lineage (PV_LINEAGE=shadow|enforce).
    lineage: LineageRef | None = None


class OutcomeRequest(BaseModel):
    decision_id: str = Field(min_length=1)
    status: str = Field(pattern="^(ok|error|refused|indeterminate)$")
    detail: str = ""
    response_digest: str = Field(default="", pattern=r"^$|^sha256:[0-9a-f]{64}$")
    # status=ok requires dispatched=true. False or omitted fails closed.
    dispatched: bool | None = None


# ---------- enforcement surface ---------------------------------------------


def _enforce_identity(principal: Principal, agent_id: str) -> None:
    """Require the authenticated credential to own the requested agent."""
    if not principal.owns(agent_id):
        raise HTTPException(
            status_code=403,
            detail=f"authenticated identity {principal.agent_id!r} cannot act as "
            f"agent {agent_id!r}",
        )


def _graph() -> DecisionGraph:
    """The decision graph to read from.

    A multi-writer recorder (PostgreSQL, or PV_MULTI_WRITER=1) does not keep
    its in-memory graph current: other processes write to the store, and the
    store is authoritative. Reading the in-memory graph there would answer
    from a startup snapshot (an outcome for a newer decision would 404, and
    /v1/verify would check nothing new), so read the store instead.
    """
    recorder = state["recorder"]
    if recorder.multi_writer_safe and recorder.store is not None:
        return cast(DecisionGraph, recorder.store.load_graph())
    return cast(DecisionGraph, recorder.graph)


def _owned_decision(principal: Principal, decision_id: str):
    """Resolve a decision while preventing cross-agent disclosure."""
    g = _graph()
    try:
        record = g.lineage(decision_id)[-1]
    except KeyError:
        raise HTTPException(status_code=404, detail="unknown decision_id") from None
    if not principal.owns(record.agent_id):
        raise HTTPException(status_code=404, detail="unknown decision_id")
    return record


def _validate_decide_wire_inputs(req: DecideRequest) -> None:
    has_digest = req.expected_wire_bytes_digest is not None
    has_length = req.expected_wire_bytes_length is not None
    if has_digest != has_length:
        raise HTTPException(
            422,
            "expected_wire_bytes_digest and expected_wire_bytes_length must both be provided or both omitted",
        )
    if has_digest and (req.execution_action is None or req.dispatch_context is None):
        raise HTTPException(
            422, "wire binding requires execution_action and dispatch_context"
        )


def _validate_decide_wire_body(
    req: DecideRequest,
    execution_action: dict[str, Any],
    dispatch_context: dict[str, Any],
) -> None:
    from agent_dna.authority_v01 import AuthorityFormatError
    from agent_dna.wire_serialization_v01 import wire_bytes_digest_from_action

    try:
        derived_digest, derived_length, _ = wire_bytes_digest_from_action(
            execution_action,
            serialization=dispatch_context["serialization"],
        )
    except (AuthorityFormatError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if req.expected_wire_bytes_digest is not None:
        if req.expected_wire_bytes_digest != derived_digest:
            raise HTTPException(
                status_code=422,
                detail=(
                    "expected_wire_bytes_digest does not match the named "
                    "serialization of execution_action.parameters"
                ),
            )
        if req.expected_wire_bytes_length != derived_length:
            raise HTTPException(
                status_code=422,
                detail=(
                    "expected_wire_bytes_length does not match the named "
                    "serialization of execution_action.parameters"
                ),
            )


def _validate_decide_binding(
    req: DecideRequest,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Derive-only binding inputs for DRP 0.2. Refuse caller digests.

    Both absent -> DRP 0.1: the decision is recorded and sealed, but the
    record is audit-only and cannot mint a permit. Exactly one present ->
    422: partial binding is refused, matching DecisionRecorder.record.
    """
    from agent_dna.action_v01 import validate_execution_action
    from agent_dna.authority_v01 import AuthorityFormatError
    from agent_dna.dispatch_context_v01 import validate_dispatch_context

    has_action = req.execution_action is not None
    has_dispatch = req.dispatch_context is not None
    _validate_decide_wire_inputs(req)
    if not has_action and not has_dispatch:
        return None, None
    if has_action ^ has_dispatch:
        raise HTTPException(
            status_code=422,
            detail=(
                "execution_action and dispatch_context must both be provided "
                "for a mintable decision, or both omitted for audit-only"
            ),
        )

    raw_action = req.execution_action or {}
    raw_dispatch = req.dispatch_context or {}
    if "action_digest" in raw_action or "dispatch_context_digest" in raw_dispatch:
        raise HTTPException(
            status_code=422,
            detail=(
                "caller-authored digests are refused; provide execution_action "
                "and dispatch_context fields only"
            ),
        )
    try:
        execution_action = dict(validate_execution_action(raw_action))
        dispatch_context = validate_dispatch_context(raw_dispatch)
    except (AuthorityFormatError, TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if execution_action["action"] != req.capability:
        raise HTTPException(
            status_code=422,
            detail="execution_action.action must match capability",
        )
    if execution_action["subject_key_id"] != req.agent_id:
        raise HTTPException(
            status_code=422,
            detail="execution_action.subject_key_id must match agent_id",
        )
    # Parameters / arguments must agree so arguments_digest matches EA action.
    if dict(execution_action["parameters"]) != dict(req.arguments or {}):
        raise HTTPException(
            status_code=422,
            detail="execution_action.parameters must match arguments",
        )

    _validate_decide_wire_body(req, execution_action, dispatch_context)

    return execution_action, dispatch_context


def _approval_context_for(
    req: DecideRequest,
    principal: Principal,
    execution_action: dict[str, Any] | None,
) -> ApprovalContext | None:
    """ADR 0020: refuse an approval block outright when it cannot be judged.

    No approver bundle pinned, or an audit-only decide: 422 before any
    decision is made, so a misconfigured deployment never records an
    approval it did not verify.
    """
    if req.approval is None:
        return None
    engine = state.get("engine")
    core = getattr(engine, "engine", engine)
    if getattr(core, "approvals", None) is None:
        raise HTTPException(
            status_code=422,
            detail={
                "reason_code": APPROVAL_NOT_CONFIGURED,
                "detail": "approval presented but no approver trust bundle is "
                "pinned (PV_APPROVER_TRUST_BUNDLE)",
            },
        )
    if execution_action is None:
        raise HTTPException(
            status_code=422,
            detail={
                "reason_code": APPROVAL_REQUIRES_BOUND_DECISION,
                "detail": "an approval requires a mintable decide "
                "(execution_action and dispatch_context)",
            },
        )
    from agent_dna.action_v01 import execution_action_digest

    identities = {
        req.agent_id,
        principal.agent_id or "",
        principal.credential_fingerprint,
    }
    return ApprovalContext(
        expected_action_digest=execution_action_digest(execution_action),
        requester_identities=frozenset(i for i in identities if i),
    )


def _decide_or_block_undeclared(
    req: DecideRequest,
    monitor: RuntimeMonitor,
    action: AgentAction,
    evidence: dict[str, Any],
    approval_context: Any,
    execution_action: dict[str, Any] | None,
    dispatch_context: dict[str, Any] | None,
) -> DecisionResult:
    """ADR 0025: a bound request its capability does not declare is a sealed
    BLOCK, decided before the engine runs, so it spends no grant budget and
    consumes no approval. The credential audience is checked again at mint."""
    registry: OperationRegistry | None = state.get("operation_registry")
    if (
        registry is not None
        and execution_action is not None
        and dispatch_context is not None
    ):
        match = registry.check(req.capability, execution_action, dispatch_context)
        if not match.ok:
            return operation_block(req.capability, req.agent_id, match)
    return monitor.process(
        action,
        evidence=evidence or None,
        approval=req.approval,
        approval_context=approval_context,
    )


def _decided_permit_evidence(result: DecisionResult) -> dict[str, str]:
    """ADR 0026: the references a permit for this decision will cite, fixed
    now from this server's configuration and the grant the engine used."""
    evidence = state.get("permit_evidence")
    if evidence is None:
        evidence = state["permit_evidence"] = _permit_evidence(
            state.get("operation_registry")
        )
    grant_id = getattr(result, "grant_id", None)
    grant: dict[str, Any] | None = None
    if isinstance(grant_id, str) and grant_id:
        authorizer = getattr(state.get("engine"), "authorizer", None)
        snapshot = getattr(authorizer, "snapshot_of", None)
        try:
            grant = snapshot(grant_id) if snapshot is not None else None
        except KeyError:
            grant = None
        if grant is None:
            grant = {"grant_id": grant_id}
    return decided_evidence(policy_bundle=evidence["policy_bundle_digest"], grant=grant)


@app.post("/v1/decide")
def decide(req: DecideRequest, principal: FullPrincipal):
    _enforce_identity(principal, req.agent_id)
    execution_action, dispatch_context = _validate_decide_binding(req)
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
    approval_context = _approval_context_for(req, principal, execution_action)
    monitor = _monitor_for(req.agent_id)
    started = _time.perf_counter()
    evidence = dict(req.evidence or {})
    if execution_action is not None and dispatch_context is not None:
        # The sealed destination, METHOD+path and resource are what the
        # permit will bind and the receiver will execute. Expose them to
        # customer policy under a reserved key that callers cannot supply,
        # so rules can match on where and how the bytes are sent, e.g.
        #   {"field": "evidence.bound.operation", "operator": "not_in",
        #    "value": ["POST /v1/refunds"]}  -> block
        evidence["bound"] = {
            "destination": dispatch_context["destination"],
            "operation": dispatch_context["operation"],
            "transport": dispatch_context["transport"],
            "wire_content_type": dispatch_context["wire_content_type"],
            "resource": execution_action["resource"],
            "subject_principal": execution_action["subject_principal"],
            "action": execution_action["action"],
        }
    elif "bound" in evidence:
        raise HTTPException(
            status_code=422,
            detail="evidence.bound is reserved for sealed dispatch values",
        )
    if "shell" in evidence:
        raise HTTPException(
            status_code=422,
            detail="evidence.shell is reserved; the runtime derives it",
        )
    result = _decide_or_block_undeclared(
        req,
        monitor,
        action,
        evidence,
        approval_context,
        execution_action,
        dispatch_context,
    )
    result = escalate_with_cross_agent(
        state.get("cross_agent"),
        execution_id=execution_id,
        agent_id=req.agent_id,
        capability=req.capability,
        result=result,
    )
    observe_decide_latency(_time.perf_counter() - started)

    # ADR 0021: server-derived lineage. Escalate-only; enforce blocks on
    # any finding, shadow reports without changing the verdict.
    ledger: LineageLedger | None = state.get("lineage")
    mode = state.get("lineage_mode", "off")
    lineage_ctx = None
    lineage_claimed = False
    if ledger is not None:
        lineage_ctx = ledger.resolve(
            agent_id=req.agent_id,
            capability=req.capability,
            lineage=req.lineage.model_dump() if req.lineage else None,
        )
        if mode == "enforce":
            result = escalate_with_lineage(result, lineage_ctx.findings)
            if (
                result.decision is Decision.ALLOW
                and lineage_ctx.approves_record_hash is not None
            ):
                lineage_claimed = ledger.claim_approval(lineage_ctx)
                if not lineage_claimed:
                    finding = LineageFinding(
                        LINEAGE_ALREADY_APPROVED,
                        "this initiate has already been approved once",
                    )
                    lineage_ctx.findings.append(finding)
                    result = escalate_with_lineage(result, [finding])

    enforcer = state.get("cross_agent")
    require_eid = bool(
        enforcer is not None and getattr(enforcer, "require_execution_id", False)
    )
    engine = state.get("engine")
    authorizer = getattr(engine, "authorizer", None)
    runtime = state.get("runtime")
    attach_control_posture(
        result,
        {
            "authorization_mode": authorization_mode_of(authorizer),
            "cross_agent_attached": enforcer is not None,
            "cross_agent_require_execution_id": require_eid,
            "cross_agent_correlated": bool(execution_id) and enforcer is not None,
            "loop_events_required": bool(
                getattr(runtime, "loop_events_required", False)
            ),
            "lineage_mode": mode,
            # ADR 0026: what a permit for this decision may cite.
            PERMIT_EVIDENCE_KEY: _decided_permit_evidence(result),
        },
    )

    record = state["recorder"].record(
        action,
        result,
        execution_action=execution_action,
        dispatch_context=dispatch_context,
    )

    content: dict[str, Any] = {
        "decision": result.decision.value,
        "triggered_by": result.triggered_by,
        "reason": result.reason,
        "execution_id": execution_id,
        "record": record.to_dict(),
    }
    if ledger is not None and lineage_ctx is not None:
        ledger.record(
            lineage_ctx,
            record_hash=record.record_hash,
            decision_id=record.decision_id,
            decision=result.decision.value,
            claimed=lineage_claimed,
        )
        content["lineage"] = lineage_ctx.report(mode)
    return JSONResponse(status_code=STATUS_MAP[result.decision], content=content)


@app.post("/v1/outcome")
def outcome(req: OutcomeRequest, principal: FullPrincipal):
    _owned_decision(principal, req.decision_id)
    if req.status == "ok" and req.dispatched is not True:
        raise HTTPException(
            status_code=409,
            detail="status=ok requires dispatched=true",
        )
    try:
        event = state["recorder"].report_outcome(
            req.decision_id,
            req.status,
            req.detail,
            response_digest=req.response_digest,
            dispatched=req.dispatched,
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
    g = _graph()
    return {
        "agent_id": agent_id,
        "records": [r.to_dict() for r in g.find_by_agent(agent_id)],
    }


@app.get("/v1/blocked")
def blocked(principal: FullPrincipal):
    g = _graph()
    rows = g.find_blocked()
    if not principal.authentication_disabled:
        rows = [r for r in rows if r.agent_id == principal.agent_id]
    return {"blocked": [r.to_dict() for r in rows]}


@app.get("/v1/divergent")
def divergent(principal: FullPrincipal):
    g = _graph()
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
    return {"lineage": [r.to_dict() for r in _graph().lineage(decision_id)]}


# ---------- audit surface -------------------------------------------------------


@app.get("/v1/revocations", dependencies=[Depends(require_audit_or_full_key)])
def revocations():
    """Signed list of revoked permits, suspended agents and organisation.

    Signed with the execution-authorization key receivers already pin, so a
    receiver gate verifies it like a permit. Short validity: receivers must
    refresh, and refuse everything when their copy expires.
    """
    signer = _pv_load_signer()
    ttl = int(os.environ.get("PV_REVOCATION_LIST_TTL_SECONDS", "30"))
    try:
        return build_revocation_list(
            state["store"],
            organisation_id=signer["trust_bundle"]["organisation_id"],
            signing_key=signer["signing_key"],
            signer_key_id=signer["key_id"],
            validity=_timedelta(seconds=max(1, ttl)),
        )
    except SignerError as exc:
        raise HTTPException(
            status_code=503, detail="revocation list signer unavailable"
        ) from exc


@app.get("/v1/flows/{flow_id}", dependencies=[Depends(require_audit_or_full_key)])
def flow_export(flow_id: str):
    """ADR 0021: sealed lineage events of one multi-agent flow.

    Audit or full scope. Verify offline with tools/verify_lineage.py.
    """
    ledger: LineageLedger | None = state.get("lineage")
    if ledger is None:
        raise HTTPException(status_code=404, detail="lineage is not enabled")
    events = ledger.export_flow(flow_id)
    if not events:
        raise HTTPException(status_code=404, detail="unknown flow")
    return {"flow_id": flow_id, "spec": LINEAGE_EVENT_SPEC, "events": events}


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
    chains = _graph().verify_all()
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
        _log.error("readiness: store ping failed", exc_info=exc)
        return JSONResponse(
            status_code=503,
            content={
                "status": "not_ready",
                "reason": "store_unavailable",
                "detail": type(exc).__name__,
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
    # The TLS client key that will present this permit (ADR 0022). Required
    # when PV_PRESENTER_BUNDLE is set, and must be pinned there for the agent.
    presenter_identity_digest: str | None = Field(default=None, pattern=_PV_DIGEST)

    decision_receipt_digest: str = Field(pattern=_PV_DIGEST)
    approval_artifact_digest: str | None = Field(default=None, pattern=_PV_DIGEST)
    # ADR 0026: with PV_PERMIT_EVIDENCE=server (the secure-profile default)
    # the server fills these from the sealed decision; a caller may omit them
    # or repeat the sealed values, never replace them. With =caller they are
    # required and signed as the caller's assertions.
    authority_receipt_digest: str | None = Field(default=None, pattern=_PV_DIGEST)
    state_snapshot_digest: str | None = Field(default=None, pattern=_PV_DIGEST)
    policy_bundle_digest: str | None = Field(default=None, pattern=_PV_DIGEST)
    obligations_digest: str | None = Field(default=None, pattern=_PV_DIGEST)
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
        # A seed file, or an awskms:/gcpkms: reference (agent_dna.key_custody).
        signing_key = signer_from_seed_file(key_path)
        trust_bundle = _pv_json.loads(Path(bundle_path).read_text())
    except (OSError, ValueError, KeyError, TypeError, SignerError) as exc:
        raise HTTPException(
            status_code=503,
            detail=f"signer material unreadable: {type(exc).__name__}",
        ) from exc

    # The key id comes from the bundle entry that IS this key, with the
    # signer usage; a key the bundle does not pin would mint permits that
    # every receiver rejects, so refuse instead.
    public = _pv_encode_public_key(signing_key)
    key_ids = [
        key.get("key_id")
        for key in trust_bundle.get("keys") or []
        if isinstance(key, dict)
        and key.get("public_key") == public
        and "execution_authorization_signer" in (key.get("usages") or [])
    ]
    if len(key_ids) != 1 or not key_ids[0]:
        raise HTTPException(
            status_code=503,
            detail="execution signer key is not pinned as execution_authorization_signer "
            "in PV_TRUST_BUNDLE",
        )

    _pv_signer_cache["signing_key"] = signing_key
    _pv_signer_cache["trust_bundle"] = trust_bundle
    _pv_signer_cache["key_id"] = key_ids[0]
    return _pv_signer_cache


def _pv_rfc3339(moment: _datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _authorize_refusal(status_code: int, reason_code: str, detail: str) -> NoReturn:
    raise HTTPException(
        status_code=status_code,
        detail={"reason_code": reason_code, "detail": detail},
    )


def _resolve_presenter(req: AuthorizeRequest) -> str | None:
    """The presenter to bind, checked against the pinned bundle."""
    bundle: PresenterBundle | None = state.get("presenter_bundle")
    requested = req.presenter_identity_digest
    if bundle is None:
        if requested is not None:
            _authorize_refusal(
                422,
                AUTHORIZE_PRESENTER_UNCONFIGURED,
                "presenter binding requested but PV_PRESENTER_BUNDLE is not "
                "configured; a caller-supplied presenter cannot be vouched for",
            )
        return None
    if requested is None:
        _authorize_refusal(
            403,
            AUTHORIZE_PRESENTER_REQUIRED,
            "presenter_identity_digest is required: every permit must name "
            "the TLS client key that will present it",
        )
    if bundle.organisation_id != req.organisation_id or requested not in bundle.allowed(
        req.agent_id
    ):
        _authorize_refusal(
            403,
            AUTHORIZE_PRESENTER_NOT_PINNED,
            "presenter_identity_digest is not pinned for this agent",
        )
    return requested


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
        dispatch=req.dispatch,
        expected_wire_bytes_digest=req.expected_wire_bytes_digest,
        expected_wire_bytes_length=req.expected_wire_bytes_length,
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
        report = discover_loops(security_events, LoopPolicy(normalize_agent_ids=True))
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


_NO_APPROVAL_DIGEST = "sha256:" + "0" * 64


def _revoked_grant_for(record: dict[str, Any]) -> str | None:
    """Grant id of a sealed decision if that grant is durably revoked."""
    if record.get("triggered_by") == TRIGGERED_BY_APPROVAL:
        return None  # approval_ref names an approval artifact, not a grant
    grant_id = record.get("approval_ref")
    engine = state.get("engine")
    authorizer = getattr(engine, "authorizer", None)
    ledger = getattr(authorizer, "revocation_ledger", None)
    if ledger is None or not isinstance(grant_id, str):
        return None
    return grant_id if ledger.is_revoked(grant_id) is not None else None


def _grant_expires_at(grant_id: str) -> float | None:
    authorizer = getattr(state.get("engine"), "authorizer", None)
    lookup = getattr(authorizer, "expires_at_of", None)
    if lookup is None:
        raise KeyError(grant_id)  # a grant id with no registry to vouch for it
    return lookup(grant_id)


def _authority_deadline_for(
    record: dict[str, Any], window: AuthorizationWindow
) -> AuthorityDeadline:
    store = state.get("store")
    stored = getattr(store, "approval_not_after", None)
    try:
        return authority_deadline(
            record,
            decision_window_seconds=window.decision_window_seconds,
            approval_not_after=stored if stored is not None else (lambda _d: None),
            grant_expires_at=_grant_expires_at,
        )
    except AuthorityUnknownError as exc:
        _authorize_refusal(403, AUTHORIZE_AUTHORITY_UNKNOWN, str(exc))


def _require_declared_operation(
    record: dict[str, Any], req: AuthorizeRequest
) -> dict[str, str] | None:
    """ADR 0025: the sealed capability must declare this exact request."""
    registry: OperationRegistry | None = state.get("operation_registry")
    if registry is None:
        if _secure_profile_on():
            _authorize_refusal(
                403,
                AUTHORIZE_OPERATIONS_REQUIRED,
                "PV_SECURE_PROFILE requires PV_OPERATIONS_FILE to mint",
            )
        return None
    match = registry.check(str(record.get("capability")), req.action, req.dispatch)
    if not match.ok:
        _authorize_refusal(
            403,
            AUTHORIZE_OPERATION_NOT_DECLARED
            if match.reason_code == OPERATION_NOT_DECLARED
            else AUTHORIZE_OPERATION_MISMATCH,
            match.detail,
        )
    return {"operation_id": str(match.operation_id), "registry_digest": registry.digest}


def _permit_evidence_for(
    record: dict[str, Any], req: AuthorizeRequest
) -> tuple[dict[str, str], list[str]]:
    """ADR 0026: the four evidence references the permit will carry, and
    which of them are the caller's assertions rather than sealed values."""
    evidence = state.get("permit_evidence")
    if evidence is None:
        evidence = state["permit_evidence"] = _permit_evidence(
            state.get("operation_registry")
        )
    supplied = {
        "policy_bundle_digest": req.policy_bundle_digest,
        "authority_receipt_digest": req.authority_receipt_digest,
        "state_snapshot_digest": req.state_snapshot_digest,
        "obligations_digest": req.obligations_digest,
    }
    sealed = sealed_evidence(record)
    if evidence["mode"] != SERVER:
        # Legacy: a caller value is signed as given; an omitted one falls
        # back to the sealed value.
        chosen: dict[str, str] = {}
        missing = []
        for name, value in supplied.items():
            if value is not None:
                chosen[name] = value
            elif sealed is not None:
                chosen[name] = sealed[name]
            else:
                missing.append(name)
        if missing:
            _authorize_refusal(
                422,
                AUTHORIZE_EVIDENCE_REQUIRED,
                "this decision carries no sealed permit evidence; "
                "PV_PERMIT_EVIDENCE=caller requires " + ", ".join(missing),
            )
        asserted = [
            name
            for name, value in supplied.items()
            if value is not None and (sealed is None or value != sealed[name])
        ]
        return chosen, asserted
    if sealed is None:
        _authorize_refusal(
            403,
            AUTHORIZE_EVIDENCE_UNKNOWN,
            "this decision carries no sealed permit evidence (decided before "
            "ADR 0026, or not through /v1/decide); decide again",
        )
    if sealed["policy_bundle_digest"] != evidence["policy_bundle_digest"]:
        _authorize_refusal(
            403,
            AUTHORIZE_POLICY_CHANGED,
            "the policy, grants or operations configuration differs from the "
            "one that made this decision; decide again",
        )
    mismatch = first_mismatch(sealed, supplied)
    if mismatch is not None:
        _authorize_refusal(
            403,
            AUTHORIZE_EVIDENCE_MISMATCH,
            f"{mismatch.field} {mismatch.supplied} is not the sealed "
            f"{mismatch.sealed}; omit it to use the sealed value",
        )
    return sealed, []


@app.post("/v1/authorize")
def authorize(req: AuthorizeRequest, principal: FullPrincipal):  # noqa: C901
    """Issue execution authority bound to a sealed ALLOW and exact bytes."""

    _enforce_identity(principal, req.agent_id)
    record = _require_sealed_allow_for_authorize(req)
    if record.get("triggered_by") == TRIGGERED_BY_APPROVAL and (
        not req.approval_artifact_digest
        or req.approval_artifact_digest != record.get("approval_ref")
    ):
        # ADR 0020: the permit must name the approval that produced the ALLOW.
        _authorize_refusal(
            403,
            AUTHORIZE_APPROVAL_MISMATCH,
            "approval-triggered ALLOW mints only with its sealed approval digest",
        )
    if record.get("triggered_by") != TRIGGERED_BY_APPROVAL and (
        req.approval_artifact_digest not in (None, _NO_APPROVAL_DIGEST)
    ):
        # A permit must never claim a human approval that did not happen.
        # null or the all-zero placeholder (used by shipped partner and
        # receiver kits) both mean "no approval"; any real digest is refused.
        _authorize_refusal(
            403,
            AUTHORIZE_APPROVAL_MISMATCH,
            "approval_artifact_digest is only valid for an approval-triggered ALLOW",
        )

    revoked_grant = _revoked_grant_for(record)
    if revoked_grant is not None:
        _authorize_refusal(
            403,
            AUTHORIZE_GRANT_REVOKED,
            f"the grant behind this decision was revoked ({revoked_grant})",
        )

    signer = _pv_load_signer()
    trust_bundle = signer["trust_bundle"]

    if req.organisation_id != trust_bundle["organisation_id"]:
        raise HTTPException(
            status_code=403,
            detail="organisation does not match the pinned trust bundle",
        )

    runtime = state.get("runtime")
    loop_required = bool(getattr(runtime, "loop_events_required", False))
    loop_report: dict[str, Any] | None = None
    loop_ran = False
    if req.security_events is not None:
        loop_report = _authorize_loop_gate(req.security_events)
        loop_ran = True
    elif loop_required:
        raise HTTPException(
            status_code=422,
            detail={
                "reason_code": AUTHORIZE_LOOP_EVENTS_REQUIRED,
                "detail": (
                    "security_events required when PV_LOOP_EVENTS_REQUIRED "
                    "is enabled; omit is not a skip"
                ),
            },
        )

    store = state.get("store")
    if store is None or not hasattr(store, "claim_or_replay_mint"):
        raise HTTPException(
            status_code=503,
            detail="mint claim ledger is not available",
        )

    window = state.get("authorization_window")
    if not isinstance(window, AuthorizationWindow):
        # Only reachable if the lifespan did not run; refuse rather than guess.
        raise HTTPException(
            status_code=503,
            detail="authorization window is not configured",
        )
    presenter = _resolve_presenter(req)
    now = _datetime.now(UTC)
    deadline = _authority_deadline_for(record, window)
    # Permit times are whole seconds; round the end down so the permit can
    # never be valid past it, and refuse when no whole second is left.
    authority_end = deadline.not_after.replace(microsecond=0)
    if now >= authority_end:
        _authorize_refusal(
            403,
            AUTHORIZE_AUTHORITY_EXPIRED,
            f"the authority behind this decision ended at "
            f"{_pv_rfc3339(authority_end)} ({deadline.basis}); decide again",
        )
    operation = _require_declared_operation(record, req)
    evidence, caller_asserted = _permit_evidence_for(record, req)
    # A permit never outlives the approval, grant or decision behind it.
    expires_at = _pv_rfc3339(
        min(now + _timedelta(seconds=window.ttl_seconds), authority_end)
    )
    minted_at = _pv_rfc3339(now)
    not_before = _pv_rfc3339(now - _timedelta(seconds=window.not_before_leeway_seconds))
    bindings = mint_bindings_digest(
        organisation_id=req.organisation_id,
        agent_id=req.agent_id,
        principal_id=principal.credential_fingerprint,
        action=req.action,
        dispatch=req.dispatch,
        expected_wire_bytes_digest=req.expected_wire_bytes_digest,
        expected_wire_bytes_length=req.expected_wire_bytes_length,
        expected_peer_identity_digest=req.expected_peer_identity_digest,
        decision_receipt_digest=req.decision_receipt_digest,
        authority_receipt_digest=evidence["authority_receipt_digest"],
        approval_artifact_digest=req.approval_artifact_digest,
        state_snapshot_digest=evidence["state_snapshot_digest"],
        policy_bundle_digest=evidence["policy_bundle_digest"],
        obligations_digest=evidence["obligations_digest"],
        expected_presenter_identity_digest=presenter,
    )

    def _mint_authorization() -> dict[str, Any]:
        unsigned = {
            "spec": _PV_EA_SPEC if presenter is None else _PV_EA_SPEC_V02,
            "canonicalization": _PV_CANON,
            "execution_authorization_id": f"eauth-{_uuid.uuid4()}",
            "organisation_id": req.organisation_id,
            "request_id": req.request_id,
            "issued_at": not_before,
            "not_before": not_before,
            "expires_at": expires_at,
            "nonce": _uuid.uuid4().hex,
            "decision_receipt_digest": req.decision_receipt_digest,
            "authority_receipt_digest": evidence["authority_receipt_digest"],
            "approval_artifact_digest": req.approval_artifact_digest,
            "action": req.action,
            "action_digest": _pv_sha256_digest(req.action),
            "expected_wire_bytes_digest": req.expected_wire_bytes_digest,
            "expected_wire_bytes_length": req.expected_wire_bytes_length,
            "expected_peer_identity_digest": req.expected_peer_identity_digest,
            "dispatch": req.dispatch,
            "state_snapshot_digest": evidence["state_snapshot_digest"],
            "policy_bundle_digest": evidence["policy_bundle_digest"],
            "trust_bundle_digest": _pv_sha256_digest(trust_bundle),
            "obligations_digest": evidence["obligations_digest"],
            "max_uses": 1,
            "signer_key_id": signer["key_id"],
        }
        if presenter is not None:
            unsigned["expected_presenter_identity_digest"] = presenter
        return _pv_sign_ea(unsigned, signer["signing_key"])

    try:
        mint_result = store.claim_or_replay_mint(
            decision_id=record["decision_id"],
            organisation_id=req.organisation_id,
            agent_id=req.agent_id,
            principal_id=principal.credential_fingerprint,
            bindings_digest=bindings,
            now=now,
            expires_at=expires_at,
            minted_at=minted_at,
            authorization_factory=_mint_authorization,
            trust_bundle=trust_bundle,
        )
    except sqlite3.OperationalError:
        _authorize_refusal(
            503,
            AUTHORIZE_STORE_UNAVAILABLE,
            "mint claim ledger is unavailable",
        )
    except sqlite3.DatabaseError:
        _authorize_refusal(
            503,
            AUTHORIZE_STORE_UNAVAILABLE,
            "mint claim ledger is unavailable",
        )
    except SignerError as exc:
        # KMS unreachable, refused, or answered with a bad signature: no
        # permit, and the mint claim rolled back with the transaction.
        _log.error("execution signer unavailable: %s", exc)
        _authorize_refusal(
            503,
            AUTHORIZE_SIGNER_UNAVAILABLE,
            "execution authorization signer is unavailable",
        )
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=422,
            detail="execution authorization rejected",
        ) from None
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="internal mint failure",
        ) from None

    mint_status = mint_result[0]
    authorization = mint_result[1]
    stored_bundle = mint_result[2] if len(mint_result) > 2 else None

    # Revocation that committed while this mint was being claimed: the
    # revoke scan may not have seen this permit, so suspend it here and
    # refuse to hand it out (grant_revocation module docstring).
    late_revocation = _revoked_grant_for(record)
    if late_revocation is not None and isinstance(authorization, dict):
        store.suspend(
            "authorization",
            str(authorization.get("execution_authorization_id")),
            reason=f"grant revoked during mint ({late_revocation})",
            suspended_by="authorize",
            suspended_at=minted_at,
        )
        _authorize_refusal(
            403,
            AUTHORIZE_GRANT_REVOKED,
            f"the grant behind this decision was revoked ({late_revocation})",
        )

    if mint_status == "conflict":
        _authorize_refusal(
            403,
            AUTHORIZE_PERMIT_BINDING_CONFLICT,
            "mint bindings do not match the live permit for this decision",
        )
    if mint_status == "consumed":
        _authorize_refusal(
            409,
            AUTHORIZE_PERMIT_ALREADY_CONSUMED,
            "the live permit for this decision has already been consumed",
        )
    if mint_status == "expired":
        _authorize_refusal(
            409,
            AUTHORIZE_PERMIT_EXPIRED,
            "the live permit for this decision has expired; recovery is deferred",
        )
    if mint_status == "indeterminate":
        _authorize_refusal(
            409,
            AUTHORIZE_PERMIT_INDETERMINATE,
            "an indeterminate outcome forbids another mint for this decision",
        )
    if mint_status == "missing_trust_bundle":
        _authorize_refusal(
            409,
            AUTHORIZE_PERMIT_TRUST_BUNDLE_MISSING,
            "stored permit is missing its original trust bundle",
        )
    if mint_status == "trust_bundle_digest_mismatch":
        _authorize_refusal(
            409,
            AUTHORIZE_PERMIT_TRUST_BUNDLE_DIGEST_MISMATCH,
            "stored trust bundle does not match the authorization digest",
        )
    if authorization is None:
        raise HTTPException(
            status_code=500,
            detail="mint claim returned no authorization",
        )

    body: dict[str, Any] = {
        "authorization": authorization,
        # ADR 0025: which declared operation this permit was checked against.
        "operation": operation,
        # ADR 0026: who chose the permit's four evidence references.
        "evidence": {
            "mode": state["permit_evidence"]["mode"],
            **evidence,
            "caller_asserted": caller_asserted,
        },
        "trust_bundle": stored_bundle if stored_bundle is not None else trust_bundle,
        "at_time": _pv_rfc3339(now),
        # Operator posture: whether loop discovery ran (EA schema is closed;
        # this sits beside the permit for adapter retention).
        "loop_discovery": {
            "required": loop_required,
            "ran": loop_ran,
        },
    }
    if loop_report is not None:
        body["loop_discovery"].update(
            {
                "decision": loop_report["decision"],
                "report_id": loop_report["report_id"],
                "input_digest": loop_report["input_digest"],
            }
        )
    return body
