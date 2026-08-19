"""
Production composition root (audit Commit set 3).

One builder constructs the ENTIRE enforcement stack; every transport
(HTTP API, MCP connector, future harnesses) consumes the same
ProductionRuntime. Before this existed, the HTTP API composed only
scorer+UAAL while grants, policy, consensus, economics, the breaker,
and cross-agent enforcement sat in the repo unwired -- components
that exist but are not composed protect nothing.

Attachment policy (honesty over surprise):
  * evidence-gated levels (UAAL, consensus, economics) attach ALWAYS
    -- absent evidence they skip, never silently pass, so attaching
    is free and truthful;
  * verdict-altering levels that require configuration (customer
    policy / OPA, capability grants) attach ONLY when configured --
    an empty grant registry would convert every ALLOW into
    REQUIRE_APPROVAL by surprise;
  * the circuit breaker attaches always with whatever thresholds are
    configured; unconfigured thresholds are inert (a breaker that
    never trips still provides pre-gate + manual-trip machinery);
  * behavioral invariants (learned, L1) require a trained profile and
    are not attached until one is configured -- stated in the
    manifest, not hidden.

The runtime carries a composition MANIFEST: exactly which levels are
attached, why the rest are not, and the calibration caveat (synthetic
scorer until a real execution trace is wired -- the openly stated
binding constraint). GET /v1/runtime serves it.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .adapters import synthetic_normal_trace
from .apikeys import ApiKeyRegistry
from .circuit_breaker import BreakerConfig, CircuitBreaker, GuardedEngine
from .connector.adapters.exact_byte_http import (
    ExactByteHttpDispatcher,
    WitnessSigner,
)
from .connector.adapters.execution_trust import (
    DISPATCH_WITNESS_KEY_ENV,
    EXECUTION_TRUST_BUNDLE_ENV,
    load_execution_trust_bundle,
)
from .connector.adapters.sidecar_transport import TlsHttpsSidecarTransport
from .consensus import ConsensusChecker
from .decision import DecisionEngine
from .decision_recorder import DecisionRecorder
from .dynamics import BehaviorDynamics
from .economics import CostAnomalyChecker
from .grants import GrantRegistry
from .manifold import CapabilityManifold
from .open_authorizer import OpenAuthorizer
from .runtime import RuntimeMonitor
from .scorer import DriftScorer
from .signer_python import (
    KEY_ENV,
    TRUSTED_KEYS_ENV,
    ReceiptSigner,
    parse_trusted_keys,
)
from .sqlite_store import SQLiteDecisionStore
from .trace import AgentAction, ExecutionTrace
from .uaal_layer import UAALConstraintChecker


def _env_flag(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).lower() in ("1", "true", "yes", "on")


def _env_float(name: str) -> float | None:
    v = os.getenv(name)
    return float(v) if v not in (None, "") else None


def _env_int(name: str) -> int | None:
    v = os.getenv(name)
    return int(v) if v not in (None, "") else None


def _csv_frozenset(name: str) -> frozenset[str]:
    raw = os.getenv(name, "")
    return frozenset(part.strip() for part in raw.split(",") if part.strip())


@dataclass
class RuntimeConfig:
    db_path: str = "data/privatevault.db"
    keys_file: str | None = None
    policy_file: str | None = None  # customer YAML/JSON rules
    opa_endpoint: str | None = None  # OPA adapter (policy_file wins)
    opa_policy_path: str = "agent/governance"
    opa_deadline: float = 1.0  # TOTAL budget, all retries
    opa_cache_ttl: int = 0  # = max policy revocation lag
    opa_token: str | None = None
    opa_client_cert: str | None = None
    opa_client_key: str | None = None
    opa_ca_bundle: str | None = None
    opa_bundle_path: str | None = None  # degraded air-gapped fallback
    replay_fields: list | None = None  # opt-in retrospective-replay input allowlist
    replay_db: str | None = None
    grants_file: str | None = None  # JSON list of capability grants
    multi_writer: bool = False
    breaker_db: str | None = None  # default: <db_path>.breaker.db
    breaker_max_decisions: int | None = None
    breaker_window_seconds: float = 60.0
    breaker_max_amount: float | None = None
    breaker_max_refusals: int | None = None
    trusted_public_keys: frozenset[str] = field(default_factory=frozenset)
    execution_trust_bundle_file: str | None = None
    egress_allowed_destinations: frozenset[str] = field(default_factory=frozenset)
    egress_allowed_audiences: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_env(cls) -> RuntimeConfig:
        return cls(
            db_path=os.environ.get("PV_DB_PATH", "data/privatevault.db"),
            keys_file=os.getenv("PV_API_KEYS_FILE"),
            policy_file=os.getenv("PV_POLICY_FILE"),
            opa_endpoint=os.getenv("PV_OPA_ENDPOINT"),
            opa_policy_path=os.getenv("PV_OPA_POLICY_PATH", "agent/governance"),
            opa_deadline=_env_float("PV_OPA_DEADLINE") or 1.0,
            opa_cache_ttl=_env_int("PV_OPA_CACHE_TTL") or 0,
            opa_token=os.getenv("PV_OPA_TOKEN"),
            opa_client_cert=os.getenv("PV_OPA_CLIENT_CERT"),
            opa_client_key=os.getenv("PV_OPA_CLIENT_KEY"),
            opa_ca_bundle=os.getenv("PV_OPA_CA_BUNDLE"),
            opa_bundle_path=os.getenv("PV_OPA_BUNDLE"),
            replay_fields=(
                [
                    f.strip()
                    for f in os.environ["PV_REPLAY_FIELDS"].split(",")
                    if f.strip()
                ]
                if os.getenv("PV_REPLAY_FIELDS")
                else None
            ),
            replay_db=os.getenv("PV_REPLAY_DB"),
            grants_file=os.getenv("PV_GRANTS_FILE"),
            multi_writer=os.getenv("PV_MULTI_WRITER", "0") == "1",
            breaker_db=os.getenv("PV_BREAKER_DB"),
            breaker_max_decisions=_env_int("PV_BREAKER_MAX_DECISIONS"),
            breaker_window_seconds=_env_float("PV_BREAKER_WINDOW_SECONDS") or 60.0,
            breaker_max_amount=_env_float("PV_BREAKER_MAX_AMOUNT"),
            breaker_max_refusals=_env_int("PV_BREAKER_MAX_REFUSALS"),
            trusted_public_keys=parse_trusted_keys(os.getenv(TRUSTED_KEYS_ENV)),
            execution_trust_bundle_file=os.getenv(EXECUTION_TRUST_BUNDLE_ENV),
            egress_allowed_destinations=_csv_frozenset(
                "PV_EGRESS_ALLOWED_DESTINATIONS"
            ),
            egress_allowed_audiences=_csv_frozenset("PV_EGRESS_ALLOWED_AUDIENCES"),
        )


@dataclass
class ProductionRuntime:
    engine: GuardedEngine
    recorder: DecisionRecorder
    store: SQLiteDecisionStore
    signer: ReceiptSigner | None
    apikeys: ApiKeyRegistry
    breaker: CircuitBreaker
    replay: Any = None
    cross_agent: Any = None
    trusted_public_keys: frozenset[str] = field(default_factory=frozenset)
    composition: dict[str, dict[str, Any]] = field(default_factory=dict)
    loop_events_required: bool = False
    execution_trust_bundle: dict[str, Any] | None = None
    egress_sidecar: ExactByteHttpDispatcher | None = None

    def monitor(self) -> RuntimeMonitor:
        """A per-agent monitor bound to this runtime's recorder --
        mirrors both api/server._monitor_for and the connector
        middleware convention (one monitor per agent, caller-held)."""
        return RuntimeMonitor(self.engine, recorder=self.recorder)

    def middleware(self, cross_agent=None, shadow=None):
        """The canonical ConnectorMiddleware over this runtime.
        Requires an enabled key registry -- the middleware refuses to
        run open, by design. Defaults to this runtime's CABI enforcer."""
        from .connector import ConnectorMiddleware

        return ConnectorMiddleware(
            engine=self.engine,
            recorder=self.recorder,
            keys=self.apikeys,
            cross_agent=self.cross_agent if cross_agent is None else cross_agent,
            shadow=shadow,
        )


_BASELINE_CAPABILITY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,127}$")


def parse_baseline_capabilities(raw: str | None = None) -> list[str]:
    """Normalize PV_BASELINE_CAPABILITIES. Unset/empty → []. Invalid fails closed."""
    text = os.getenv("PV_BASELINE_CAPABILITIES", "") if raw is None else raw
    if not isinstance(text, str):
        raise ValueError("PV_BASELINE_CAPABILITIES: expected a comma-separated string")
    seen: set[str] = set()
    for part in text.split(","):
        cap = part.strip()
        if not cap:
            continue
        if not _BASELINE_CAPABILITY_RE.fullmatch(cap):
            raise ValueError(f"PV_BASELINE_CAPABILITIES: invalid capability {cap!r}")
        seen.add(cap)
    return sorted(seen)


def _baseline_capabilities() -> list[str]:
    """Optional extra capabilities for the synthetic drift baseline.

    Used by the Campfire evaluation so a granted sandbox write is not
    novelty-escalated. Unset in production: an explicit grant still
    leaves unknown capabilities subject to drift review.
    """
    return parse_baseline_capabilities()


def _train_scorer(extra_capabilities: list[str] | None = None) -> DriftScorer:
    # Synthetic profile until a real trace replaces it -- the binding
    # constraint, stated openly in the composition manifest.
    training = [synthetic_normal_trace(seed=i, loops=6) for i in range(8)]
    extras = extra_capabilities or []
    if extras:
        trace = ExecutionTrace(agent_id="grant-baseline")
        ts = 1_700_000_000.0
        for cap in extras:
            for _ in range(6):
                ts += 30.0
                trace.add(
                    AgentAction(
                        agent_id="grant-baseline",
                        capability=cap,
                        timestamp=ts,
                        arguments={},
                    )
                )
        training.append(trace)
    manifold = CapabilityManifold().fit(training)
    dynamics = BehaviorDynamics().fit(training)
    return DriftScorer(manifold, dynamics)


def _load_grants(path: str) -> GrantRegistry:
    """JSON list: [{agent_id, capability, granted_by?, expires_at?,
    budget?}, ...]. Malformed config fails the BUILD (loudly, at
    startup) -- never a silently empty authorizer."""
    entries = json.loads(Path(path).read_text())
    if not isinstance(entries, list):
        raise ValueError(f"{path}: expected a JSON list of grants")
    reg = GrantRegistry()
    reg.authorization_mode = "grants_file"
    for e in entries:
        reg.grant(
            agent_id=e["agent_id"],
            capability=e["capability"],
            granted_by=e.get("granted_by", "config"),
            expires_at=e.get("expires_at"),
            budget=e.get("budget"),
        )
    reg.authorization_mode = "grants_file"
    return reg


def _secure_profile_enabled() -> bool:
    return _env_flag("PV_SECURE_PROFILE", "0")


def _assert_secure_profile_preconditions(cfg: RuntimeConfig) -> None:
    """Fail closed loudly when the operator asked for secure defaults."""
    if not _secure_profile_enabled():
        return
    if _env_flag("PV_ALLOW_NO_AUTH"):
        raise RuntimeError(
            "PV_SECURE_PROFILE=1 refuses PV_ALLOW_NO_AUTH=1 — "
            "secure profile and open-development auth cannot both be set"
        )
    if not cfg.keys_file:
        raise RuntimeError(
            "PV_SECURE_PROFILE=1 requires PV_API_KEYS_FILE "
            "(real API keys; anonymous decide is refused)"
        )
    if not cfg.grants_file:
        raise RuntimeError(
            "PV_SECURE_PROFILE=1 requires PV_GRANTS_FILE "
            "(explicit grants; deny-all empty registry is not enough)"
        )
    if not os.getenv(KEY_ENV):
        raise RuntimeError(
            f"PV_SECURE_PROFILE=1 requires {KEY_ENV} "
            "(unsigned decisions are not independently verifiable)"
        )
    if not cfg.trusted_public_keys:
        raise RuntimeError(
            f"PV_SECURE_PROFILE=1 requires {TRUSTED_KEYS_ENV} "
            "(a self-attested signer is not a trust root)"
        )
    bundle_path = cfg.execution_trust_bundle_file or os.getenv(
        EXECUTION_TRUST_BUNDLE_ENV, ""
    )
    if not bundle_path:
        raise RuntimeError(
            f"PV_SECURE_PROFILE=1 requires {EXECUTION_TRUST_BUNDLE_ENV} "
            "(deployment-owned execution trust bundle; callers cannot "
            "select a trust root at dispatch time)"
        )


def _secure_profile_manifest(secure: bool) -> dict[str, str]:
    if secure:
        return {
            "status": "attached",
            "detail": (
                "PV_SECURE_PROFILE=1: API keys + grants required; "
                "receipt signer + trust roots required; "
                f"{EXECUTION_TRUST_BUNDLE_ENV} required; "
                "cross-agent execution_id and loop events required; "
                "PV_ALLOW_NO_AUTH refused"
            ),
        }
    return {
        "status": "not_configured",
        "detail": "set PV_SECURE_PROFILE=1 for secure-by-default operator path",
    }


def _compose_authorizer(
    cfg: RuntimeConfig,
) -> tuple[GrantRegistry | OpenAuthorizer, dict[str, str]]:
    if cfg.grants_file:
        authorizer = _load_grants(cfg.grants_file)
        authorizer.authorization_mode = "grants_file"
        return authorizer, {
            "status": "attached",
            "detail": f"grants: {cfg.grants_file}",
            "mode": "grants_file",
        }
    if _env_flag("PV_ALLOW_NO_AUTH"):
        return OpenAuthorizer(), {
            "status": "open_development",
            "detail": (
                "UNSAFE DEVELOPMENT ONLY — PV_ALLOW_NO_AUTH: open authorizer; "
                "capability default-deny is OFF; never use in production; "
                "mode recorded in decision evidence"
            ),
            "mode": "open",
        }
    authorizer = GrantRegistry()
    authorizer.authorization_mode = "deny_all"
    return authorizer, {
        "status": "attached",
        "detail": "deny-all empty GrantRegistry (PV_GRANTS_FILE unset); "
        "default-deny for capabilities",
        "mode": "deny_all",
    }


def build_production_runtime(
    config: RuntimeConfig | None = None,
) -> ProductionRuntime:
    cfg = config or RuntimeConfig.from_env()
    _assert_secure_profile_preconditions(cfg)
    secure = _secure_profile_enabled()
    comp: dict[str, dict[str, Any]] = {
        "secure_profile": _secure_profile_manifest(secure),
    }

    # ---- always-attached, evidence-gated levels ----
    uaal = UAALConstraintChecker()
    comp["uaal_constraint"] = {
        "status": "attached",
        "detail": "evidence-gated; absent evidence skips, never passes",
    }
    consensus = ConsensusChecker()
    comp["consensus"] = {
        "status": "attached",
        "detail": "pv-vote/1 evidence-gated quorum; ceiling REQUIRE_APPROVAL",
    }
    economics = CostAnomalyChecker()
    comp["economics"] = {
        "status": "attached",
        "detail": "evidence-gated cost/ROI checks; never blocks",
    }

    # ---- config-gated: customer policy ----
    policy: Any = None
    if cfg.policy_file:
        from .policy.checker import PolicyChecker
        from .policy.loader import load_policy_file

        policy = PolicyChecker(load_policy_file(cfg.policy_file))
        comp["policy"] = {
            "status": "attached",
            "detail": f"file rules: {cfg.policy_file}",
        }
    elif cfg.opa_endpoint:
        from .adapters_policy.opa import OPAPolicyAdapter

        policy = OPAPolicyAdapter(
            endpoint=cfg.opa_endpoint,
            policy_path=cfg.opa_policy_path,
            bundle_path=cfg.opa_bundle_path,
            cache_ttl=cfg.opa_cache_ttl,
            deadline_seconds=cfg.opa_deadline,
            token=cfg.opa_token,
            client_cert=cfg.opa_client_cert,
            client_key=cfg.opa_client_key,
            ca_bundle=cfg.opa_ca_bundle,
        )
        transport = []
        if cfg.opa_endpoint.startswith("https"):
            transport.append("mTLS" if cfg.opa_client_cert else "TLS")
        else:
            transport.append("plaintext")
        if cfg.opa_token:
            transport.append("bearer-auth")
        comp["policy"] = {
            "status": "attached",
            "detail": (
                f"OPA (fail-closed): {cfg.opa_endpoint} "
                f"[{'+'.join(transport)}, deadline {cfg.opa_deadline}s, "
                f"cache_ttl {cfg.opa_cache_ttl}s = max revocation lag]"
            ),
        }
    else:
        comp["policy"] = {
            "status": "not_configured",
            "detail": "set PV_POLICY_FILE (YAML/JSON rules) or PV_OPA_ENDPOINT",
        }

    # ---- authorization: operator-configured; never caller-skippable ----
    # Non-development: empty GrantRegistry is deny-all (default-deny).
    # Development (PV_ALLOW_NO_AUTH): OpenAuthorizer, mode recorded in
    # decision evidence — not the same as authorizer=None.
    authorizer, comp["authorization"] = _compose_authorizer(cfg)

    comp["invariant"] = {
        "status": "not_configured",
        "detail": "behavioral invariants require a trained per-agent "
        "profile; none configured",
    }
    baseline_caps = parse_baseline_capabilities()
    if baseline_caps:
        drift_detail = (
            "CALIBRATION CAVEAT: scorer trained on synthetic traces "
            "until a real execution trace is wired -- the openly stated "
            "binding constraint; PV_BASELINE_CAPABILITIES override "
            f"active: {','.join(baseline_caps)}"
        )
    else:
        drift_detail = (
            "CALIBRATION CAVEAT: scorer trained on synthetic "
            "traces until a real execution trace is wired -- the "
            "openly stated binding constraint"
        )
    comp["drift"] = {
        "status": "attached",
        "detail": drift_detail,
    }
    comp["baseline_capabilities"] = {
        "status": "attached" if baseline_caps else "not_configured",
        "capabilities": list(baseline_caps),
        "override": "true" if baseline_caps else "false",
        "detail": (
            "PV_BASELINE_CAPABILITIES trained into the synthetic drift scorer"
            if baseline_caps
            else "PV_BASELINE_CAPABILITIES unset; synthetic baseline unchanged"
        ),
    }

    engine_core = DecisionEngine(
        scorer=_train_scorer(baseline_caps),
        uaal=uaal,
        consensus=consensus,
        economics=economics,
        policy=policy,
        authorizer=authorizer,
    )

    # ---- breaker: always attached; unconfigured thresholds are inert ----
    breaker_db = cfg.breaker_db or f"{cfg.db_path}.breaker.db"
    breaker = CircuitBreaker(
        breaker_db,
        BreakerConfig(
            max_decisions=cfg.breaker_max_decisions,
            window_seconds=cfg.breaker_window_seconds,
            max_cumulative_amount=cfg.breaker_max_amount,
            max_consecutive_refusals=cfg.breaker_max_refusals,
        ),
    )
    thresholds = {
        "max_decisions": cfg.breaker_max_decisions,
        "max_cumulative_amount": cfg.breaker_max_amount,
        "max_consecutive_refusals": cfg.breaker_max_refusals,
    }
    active = {k: v for k, v in thresholds.items() if v is not None}
    comp["circuit_breaker"] = {
        "status": "attached",
        "detail": (
            f"transactional preflight; thresholds {active}"
            if active
            else "transactional preflight; no thresholds configured "
            "(inert until PV_BREAKER_* set; pre-gate and manual "
            "trip remain active)"
        ),
    }
    engine = GuardedEngine(engine_core, breaker)

    # ---- persistence + signing ----
    signer = ReceiptSigner() if os.getenv(KEY_ENV) else None
    if signer is not None and signer.public_key not in cfg.trusted_public_keys:
        breaker.close()
        raise RuntimeError(
            f"{TRUSTED_KEYS_ENV} must include the active signing public key; "
            "refusing self-attested signing mode"
        )

    store = SQLiteDecisionStore(cfg.db_path)
    comp["signing"] = {
        "status": "attached" if signer else "not_configured",
        "detail": (
            f"Ed25519 receipt signing; "
            f"{len(cfg.trusted_public_keys)} configured trust root(s)"
            if signer
            else f"set {KEY_ENV}; decisions will NOT be signed"
        ),
    }
    recorder = DecisionRecorder(
        store=store,
        signer=signer,
        multi_writer_safe=cfg.multi_writer,
    )
    comp["persistence"] = {
        "status": "attached",
        "detail": f"SQLite {cfg.db_path}"
        + (" (multi-writer safe)" if cfg.multi_writer else ""),
    }

    apikeys = ApiKeyRegistry(cfg.keys_file)
    if secure and not apikeys.enabled:
        breaker.close()
        raise RuntimeError(
            "PV_SECURE_PROFILE=1 requires at least one API key in "
            "PV_API_KEYS_FILE (registry empty or unreadable)"
        )
    comp["identity"] = {
        "status": "attached" if apikeys.enabled else "not_configured",
        "detail": (
            "credential-derived agent identity"
            if apikeys.enabled
            else "PV_API_KEYS_FILE unset -- auth DISABLED (dev only)"
        ),
    }

    replay_store = None
    if cfg.replay_fields:
        from .policy_replay import ReplayInputStore

        replay_store = ReplayInputStore(
            path=cfg.replay_db or f"{cfg.db_path}.replay.db",
            retain_fields=cfg.replay_fields,
        )
        recorder.replay_capture = replay_store.capture
        comp["policy_replay"] = {
            "status": "attached",
            "detail": (
                f"OPT-IN retrospective replay; retaining fields "
                f"{sorted(cfg.replay_fields)} in a SEPARATE store "
                f"(privacy boundary: docs/POLICY-REPLAY.md)"
            ),
        }
    else:
        comp["policy_replay"] = {
            "status": "not_configured",
            "detail": "retrospective replay OFF (PV_REPLAY_FIELDS unset); "
            "no rule-input retention",
        }

    # ---- multi-agent: definitional CABI + authorize-time loop discovery ----
    cross_agent = None
    cabi_disabled = os.getenv("PV_CROSS_AGENT", "1").lower() in ("0", "false", "no")
    # Secure profile forces these on; env alone may leave them off for
    # compatibility. Callers cannot disable via request fields.
    require_execution_id = secure or _env_flag(
        "PV_CROSS_AGENT_REQUIRE_EXECUTION_ID", "0"
    )
    loop_events_required = secure or _env_flag("PV_LOOP_EVENTS_REQUIRED", "0")
    if cabi_disabled:
        comp["cross_agent"] = {
            "status": "disabled",
            "detail": "PV_CROSS_AGENT=0; dual-control CABI not attached "
            "(operator-disabled; recorded in composition manifest)",
            "require_execution_id": "false",
        }
    else:
        from .connector.cross_agent import production_cross_agent

        cross_agent = production_cross_agent(
            require_execution_id=require_execution_id,
        )
        comp["cross_agent"] = {
            "status": "attached",
            "detail": (
                "definitional dual-control + structural approval invariants; "
                "escalation-only; attached on HTTP /v1/decide and connector; "
                + (
                    "PV_CROSS_AGENT_REQUIRE_EXECUTION_ID=1 (fail-closed without id "
                    "for configured capability prefixes)"
                    if require_execution_id
                    else "PV_CROSS_AGENT_REQUIRE_EXECUTION_ID=0 (uncorrelated "
                    "calls skip CABI; posture recorded in decision evidence)"
                )
            ),
            "require_execution_id": "true" if require_execution_id else "false",
        }
    comp["loop_discovery"] = {
        "status": "required" if loop_events_required else "authorize_gated",
        "detail": (
            "PV_LOOP_EVENTS_REQUIRED=1: /v1/authorize refuses without "
            "security_events (fail-closed)"
            if loop_events_required
            else "discover_loops at POST /v1/authorize when security_events "
            "are supplied; BLOCK/REVIEW refuse mint (fail-closed); "
            "PV_LOOP_EVENTS_REQUIRED=0 (caller may omit; operator-configured)"
        ),
        "events_required": "true" if loop_events_required else "false",
    }

    execution_bundle, sidecar = _compose_egress_sidecar(cfg, store, secure, comp)

    return ProductionRuntime(
        engine=engine,
        recorder=recorder,
        store=store,
        signer=signer,
        apikeys=apikeys,
        breaker=breaker,
        replay=replay_store,
        cross_agent=cross_agent,
        trusted_public_keys=cfg.trusted_public_keys,
        composition=comp,
        loop_events_required=loop_events_required,
        execution_trust_bundle=execution_bundle,
        egress_sidecar=sidecar,
    )


def _compose_egress_sidecar(
    cfg: RuntimeConfig,
    store: SQLiteDecisionStore,
    secure: bool,
    comp: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any] | None, ExactByteHttpDispatcher | None]:
    path = cfg.execution_trust_bundle_file or os.getenv(EXECUTION_TRUST_BUNDLE_ENV, "")
    if not path:
        comp["egress_sidecar"] = {
            "status": "not_configured",
            "detail": (
                f"set {EXECUTION_TRUST_BUNDLE_ENV} to pin a deployment-owned "
                "execution trust bundle; callers cannot select a trust root"
            ),
        }
        return None, None
    bundle = load_execution_trust_bundle(path)
    key_path = os.getenv(DISPATCH_WITNESS_KEY_ENV, "")
    if not key_path:
        if secure:
            raise RuntimeError(
                f"PV_SECURE_PROFILE=1 requires {DISPATCH_WITNESS_KEY_ENV} "
                "(sidecar-owned dispatch-witness key; not caller-supplied)"
            )
        comp["egress_sidecar"] = {
            "status": "not_configured",
            "detail": (
                f"{EXECUTION_TRUST_BUNDLE_ENV} loaded; set "
                f"{DISPATCH_WITNESS_KEY_ENV} to attach the production sidecar"
            ),
        }
        return bundle, None
    signer = _witness_signer_from_bundle(bundle, key_path)
    headers: dict[str, str] = {}
    token = os.getenv("PV_UPSTREAM_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    extra = os.getenv("PV_UPSTREAM_AUTH_HEADER", "")
    if extra:
        headers["Authorization"] = extra
    destinations = cfg.egress_allowed_destinations or _csv_frozenset(
        "PV_EGRESS_ALLOWED_DESTINATIONS"
    )
    audiences = cfg.egress_allowed_audiences or _csv_frozenset(
        "PV_EGRESS_ALLOWED_AUDIENCES"
    )
    if headers and (not destinations or not audiences) and secure:
        raise RuntimeError(
            "PV_SECURE_PROFILE=1 refuses upstream credentials without "
            "PV_EGRESS_ALLOWED_DESTINATIONS and PV_EGRESS_ALLOWED_AUDIENCES"
        )
    dispatcher = ExactByteHttpDispatcher(
        consume_ledger=store,
        witness=signer,
        trust_bundle=bundle,
        transport=TlsHttpsSidecarTransport(
            credentials_headers=headers,
            allowed_destinations=destinations,
            allowed_audiences=audiences,
        ),
    )
    comp["egress_sidecar"] = {
        "status": "attached",
        "detail": (
            "pinned execution trust bundle; sidecar-owned HTTPS/TLS transport; "
            "witness signed after send; at-most-once consume"
        ),
    }
    return bundle, dispatcher


def _witness_signer_from_bundle(bundle: dict[str, Any], key_path: str) -> WitnessSigner:
    from nacl.signing import SigningKey

    from .authority_v01 import encode_public_key

    raw = Path(key_path).read_bytes()
    try:
        key = SigningKey(raw)
    except Exception as exc:
        raise RuntimeError(
            f"{DISPATCH_WITNESS_KEY_ENV} is not a valid Ed25519 seed: {exc}"
        ) from exc
    pub = encode_public_key(key)
    witness_id = ""
    closure_id = ""
    for item in bundle.get("keys") or []:
        if not isinstance(item, dict):
            continue
        usages = set(item.get("usages") or [])
        if item.get("public_key") != pub:
            continue
        if "dispatch_witness_signer" in usages:
            witness_id = str(item.get("key_id") or "")
        if "closure_signer" in usages:
            closure_id = str(item.get("key_id") or "")
    if not witness_id:
        raise RuntimeError(
            f"{DISPATCH_WITNESS_KEY_ENV} public key is absent from the pinned "
            "execution trust bundle as dispatch_witness_signer"
        )
    if not closure_id:
        raise RuntimeError(
            f"{DISPATCH_WITNESS_KEY_ENV} public key is absent from the pinned "
            "execution trust bundle as closure_signer"
        )
    return WitnessSigner(
        signing_key=key,
        signer_key_id=witness_id,
        witness_component_id="pv-egress-sidecar",
        closure_signer_key_id=closure_id,
        closure_signing_key=key,
    )
