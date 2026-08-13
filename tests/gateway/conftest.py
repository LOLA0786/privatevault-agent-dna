"""Shared fixtures for inline MCP gateway adversarial tests."""

from __future__ import annotations

import json

import pytest

from agent_dna.advisory import AdvisorySignal, Severity
from agent_dna.apikeys import generate_key
from agent_dna.composition import RuntimeConfig, build_production_runtime
from agent_dna.gateway.credentials import UpstreamCredentials
from agent_dna.gateway.metrics import GatewayMetrics
from agent_dna.gateway.runtime import GatewayConfig, McpGateway

SECRET = "super-secret-upstream-token-xyz-9f3a"
TOOL = "crm.read_contact"


class _NeutralScorer:
    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.0,
            severity=Severity.INFO,
            reasons=[],
        )


@pytest.fixture
def agent_key(tmp_path):
    entry = generate_key("gateway-agent", scope="full")
    keys = tmp_path / "keys.json"
    keys.write_text(
        json.dumps({entry["hash"]: {"name": "gateway-agent", "scope": "full"}})
    )
    grants = tmp_path / "grants.json"
    grants.write_text(
        json.dumps(
            [
                {
                    "agent_id": "gateway-agent",
                    "capability": TOOL,
                    "granted_by": "gateway-test",
                }
            ]
        )
    )
    return {
        "key": entry["key"],
        "keys_file": str(keys),
        "grants_file": str(grants),
        "db_path": str(tmp_path / "gw.db"),
    }


@pytest.fixture
def allow_runtime(agent_key):
    rt = build_production_runtime(
        RuntimeConfig(
            db_path=agent_key["db_path"],
            keys_file=agent_key["keys_file"],
            grants_file=agent_key["grants_file"],
        )
    )
    rt.engine.scorer = _NeutralScorer()
    return rt, agent_key["key"]


@pytest.fixture
def deny_runtime(agent_key, monkeypatch):
    # Force deny-all: suite conftest opts into PV_ALLOW_NO_AUTH.
    monkeypatch.delenv("PV_ALLOW_NO_AUTH", raising=False)
    rt = build_production_runtime(
        RuntimeConfig(
            db_path=agent_key["db_path"] + ".deny",
            keys_file=agent_key["keys_file"],
            grants_file=None,
        )
    )
    assert getattr(rt.engine.authorizer, "authorization_mode", None) == "deny_all"
    rt.engine.scorer = _NeutralScorer()
    return rt, agent_key["key"]


@pytest.fixture
def credentials():
    return UpstreamCredentials(
        env={"UPSTREAM_TOKEN": SECRET},
        headers={"Authorization": f"Bearer {SECRET}"},
    )


def make_gateway(
    runtime,
    key,
    credentials,
    upstream,
    transport="stdio",
    **config_overrides,
):
    cfg = {
        "agent_api_key": key,
        "client_identity": "gateway-agent@test",
        "transport": transport,
        "upstream_timeout_s": 0.2,
        "framed": True,
        "_test_allow_inprocess": True,
    }
    cfg.update(config_overrides)
    return McpGateway(
        runtime,
        config=GatewayConfig(**cfg),
        credentials=credentials,
        upstream=upstream,
        metrics=GatewayMetrics(),
    )
