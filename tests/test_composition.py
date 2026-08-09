"""Production composition root (audit Commit set 3)."""

import importlib
import json
import time

import pytest

from agent_dna.circuit_breaker import GuardedEngine
from agent_dna.composition import RuntimeConfig, build_production_runtime
from agent_dna.trace import AgentAction


def _cfg(tmp_path, **kw):
    return RuntimeConfig(db_path=str(tmp_path / "pv.db"), **kw)


def test_default_runtime_attaches_evidence_gated_stack(tmp_path):
    rt = build_production_runtime(_cfg(tmp_path))
    assert isinstance(rt.engine, GuardedEngine)
    comp = rt.composition
    for level in (
        "uaal_constraint",
        "consensus",
        "economics",
        "circuit_breaker",
        "drift",
        "persistence",
        "cross_agent",
    ):
        assert comp[level]["status"] == "attached", level
    assert comp["loop_discovery"]["status"] == "authorize_gated"
    assert rt.cross_agent is not None
    # config-gated levels are honestly not_configured, never silently on
    assert comp["policy"]["status"] == "not_configured"
    assert comp["authorization"]["status"] == "not_configured"
    assert rt.engine.policy is None
    assert rt.engine.authorizer is None


def test_default_runtime_decides_and_records(tmp_path):
    rt = build_production_runtime(_cfg(tmp_path))
    monitor = rt.monitor()
    result = monitor.process(
        AgentAction(
            agent_id="comp-agent",
            capability="crm.read_contact",
            timestamp=time.time(),
        )
    )
    assert result.decision.value in ("allow", "require_approval")
    assert rt.recorder.graph.verify_all().get("comp-agent") is True


def test_policy_file_attaches_checker(tmp_path):
    pol = tmp_path / "policy.json"
    pol.write_text(
        json.dumps(
            {
                "policies": [
                    {
                        "id": "no-bulk-export",
                        "capability": "storage.bulk_export",
                        "outcome": "block",
                        "reason": "contractually forbidden",
                    }
                ]
            }
        )
    )
    rt = build_production_runtime(_cfg(tmp_path, policy_file=str(pol)))
    assert rt.composition["policy"]["status"] == "attached"
    from agent_dna.policy.checker import PolicyChecker

    assert isinstance(rt.engine.policy, PolicyChecker)


def test_opa_endpoint_attaches_adapter(tmp_path):
    rt = build_production_runtime(_cfg(tmp_path, opa_endpoint="http://127.0.0.1:9"))
    from agent_dna.adapters_policy.opa import OPAPolicyAdapter

    assert isinstance(rt.engine.policy, OPAPolicyAdapter)
    assert "OPA" in rt.composition["policy"]["detail"]


def test_grants_file_attaches_authorizer(tmp_path):
    gf = tmp_path / "grants.json"
    gf.write_text(
        json.dumps(
            [
                {
                    "agent_id": "comp-agent",
                    "capability": "payments.initiate_wire",
                    "granted_by": "test-config",
                }
            ]
        )
    )
    rt = build_production_runtime(_cfg(tmp_path, grants_file=str(gf)))
    assert rt.composition["authorization"]["status"] == "attached"
    assert rt.engine.authorizer.is_authorized("comp-agent", "payments.initiate_wire")


def test_malformed_grants_file_fails_the_build(tmp_path):
    gf = tmp_path / "grants.json"
    gf.write_text('{"not": "a list"}')
    with pytest.raises(ValueError, match="JSON list"):
        build_production_runtime(_cfg(tmp_path, grants_file=str(gf)))


def test_breaker_thresholds_flow_from_config(tmp_path):
    rt = build_production_runtime(_cfg(tmp_path, breaker_max_amount=1000.0))
    assert rt.breaker.config.max_cumulative_amount == 1000.0
    assert "max_cumulative_amount" in rt.composition["circuit_breaker"]["detail"]


def test_guarded_engine_setattr_reaches_inner_engine(tmp_path):
    """Regression guard for the fail-closed test-injection mechanism:
    state['engine'].scorer = Raising() must reach the REAL engine
    through the wrapper, or injected faults silently never fire."""
    rt = build_production_runtime(_cfg(tmp_path))
    sentinel = object()
    rt.engine.scorer = sentinel
    assert rt.engine.engine.scorer is sentinel


def test_api_serves_composition_manifest(tmp_path, monkeypatch):
    monkeypatch.setenv("PV_DB_PATH", str(tmp_path / "api.db"))
    monkeypatch.delenv("PV_API_KEYS_FILE", raising=False)
    monkeypatch.delenv("PV_RECEIPT_SIGNING_KEY", raising=False)
    import api.server as server

    importlib.reload(server)
    from fastapi.testclient import TestClient

    with TestClient(server.app) as c:
        r = c.get("/v1/runtime")
        assert r.status_code == 200
        comp = r.json()["composition"]
        assert comp["uaal_constraint"]["status"] == "attached"
        assert comp["consensus"]["status"] == "attached"
        assert "synthetic" in comp["drift"]["detail"]
