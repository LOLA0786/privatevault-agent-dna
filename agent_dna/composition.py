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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .adapters import synthetic_normal_trace
from .apikeys import ApiKeyRegistry
from .circuit_breaker import BreakerConfig, CircuitBreaker, GuardedEngine
from .consensus import ConsensusChecker
from .decision import DecisionEngine
from .decision_recorder import DecisionRecorder
from .dynamics import BehaviorDynamics
from .economics import CostAnomalyChecker
from .grants import GrantRegistry
from .manifold import CapabilityManifold
from .runtime import RuntimeMonitor
from .scorer import DriftScorer
from .signer_python import (
    KEY_ENV,
    TRUSTED_KEYS_ENV,
    ReceiptSigner,
    parse_trusted_keys,
)
from .sqlite_store import SQLiteDecisionStore
from .uaal_layer import UAALConstraintChecker


def _env_float(name: str) -> float | None:
    v = os.getenv(name)
    return float(v) if v not in (None, "") else None


def _env_int(name: str) -> int | None:
    v = os.getenv(name)
    return int(v) if v not in (None, "") else None


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
    trusted_public_keys: frozenset[str] = field(default_factory=frozenset)
    composition: dict[str, dict[str, str]] = field(default_factory=dict)

    def monitor(self) -> RuntimeMonitor:
        """A per-agent monitor bound to this runtime's recorder --
        mirrors both api/server._monitor_for and the connector
        middleware convention (one monitor per agent, caller-held)."""
        return RuntimeMonitor(self.engine, recorder=self.recorder)

    def middleware(self, cross_agent=None, shadow=None):
        """The canonical ConnectorMiddleware over this runtime.
        Requires an enabled key registry -- the middleware refuses to
        run open, by design."""
        from .connector import ConnectorMiddleware

        return ConnectorMiddleware(
            engine=self.engine,
            recorder=self.recorder,
            keys=self.apikeys,
            cross_agent=cross_agent,
            shadow=shadow,
        )


def _train_scorer() -> DriftScorer:
    # Synthetic profile until a real trace replaces it -- the binding
    # constraint, stated openly in the composition manifest.
    training = [synthetic_normal_trace(seed=i, loops=6) for i in range(8)]
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
    for e in entries:
        reg.grant(
            agent_id=e["agent_id"],
            capability=e["capability"],
            granted_by=e.get("granted_by", "config"),
            expires_at=e.get("expires_at"),
            budget=e.get("budget"),
        )
    return reg


def build_production_runtime(
    config: RuntimeConfig | None = None,
) -> ProductionRuntime:
    cfg = config or RuntimeConfig.from_env()
    comp: dict[str, dict[str, str]] = {}

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
    policy = None
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

    # ---- config-gated: capability grants ----
    authorizer = None
    if cfg.grants_file:
        authorizer = _load_grants(cfg.grants_file)
        comp["authorization"] = {
            "status": "attached",
            "detail": f"grants: {cfg.grants_file}",
        }
    else:
        comp["authorization"] = {
            "status": "not_configured",
            "detail": "set PV_GRANTS_FILE; attaching an empty registry "
            "would require approval for everything",
        }

    comp["invariant"] = {
        "status": "not_configured",
        "detail": "behavioral invariants require a trained per-agent "
        "profile; none configured",
    }
    comp["drift"] = {
        "status": "attached",
        "detail": "CALIBRATION CAVEAT: scorer trained on synthetic "
        "traces until a real execution trace is wired -- the "
        "openly stated binding constraint",
    }

    engine_core = DecisionEngine(
        scorer=_train_scorer(),
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

    return ProductionRuntime(
        engine=engine,
        recorder=recorder,
        store=store,
        signer=signer,
        apikeys=apikeys,
        breaker=breaker,
        replay=replay_store,
        trusted_public_keys=cfg.trusted_public_keys,
        composition=comp,
    )
