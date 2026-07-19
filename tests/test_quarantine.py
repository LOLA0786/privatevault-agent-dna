"""Quarantine enforcement (audit cleanup, Commit set 5 area).

Placeholder and self-grading code lives in experimental/ and must
never be importable from the shipped agent_dna package. If one of
these imports starts succeeding, quarantined code has leaked back
into the product -- fail loudly."""

import importlib

import pytest

QUARANTINED = [
    "agent_dna.security_validation",
    "agent_dna.marketplace",
    "agent_dna.adapters_policy.opa_cluster",
    "agent_dna.adapters_policy.opa_tls",
    "agent_dna.adapters_policy.opa_version",
    "agent_dna.adapters_policy.opa_audit",
    "agent_dna.adapters_policy.patch_opa",
    "agent_dna.store.postgres_cluster",
    # legacy MCP path (audit set 3): constructed its own partial
    # engine, took agent_id from the caller, located records by
    # last-graph-entry -- bypassed identity, grants, UAAL, breaker,
    # signing. The canonical MCP path is
    # agent_dna/connector/adapters/mcp.py over ConnectorMiddleware.
    "agent_dna.mcp_server",
    "agent_dna.mcp_gateway",
]


@pytest.mark.parametrize("module", QUARANTINED)
def test_quarantined_module_not_in_package(module):
    with pytest.raises(ImportError):
        importlib.import_module(module)


def test_production_opa_adapter_still_shipped():
    """The quarantine covers the STUBS, not the real adapter."""
    from agent_dna.adapters_policy.opa import OPAPolicyAdapter  # noqa: F401
