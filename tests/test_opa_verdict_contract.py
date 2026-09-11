"""A policy result with no verdict key must not read as 'no objection'.

The adapter's contract is {"fired": bool, "outcome": ...}. Rego written
in the conventional allow/deny idiom returns a non-empty dict carrying
neither, which is not empty and not malformed, so it passed the
existing guards and normalized to fired=False. The engine skips that:
a denial became silence on the enforcement path.
"""

import pytest

from agent_dna.adapters_policy.opa import OPAPolicyAdapter, PolicyUnavailableError

FOREIGN_IDIOMS = [
    {"allow": False},
    {"deny": True},
    {"result": "deny"},
    {"decision": "block"},
]


@pytest.fixture
def adapter():
    return OPAPolicyAdapter(endpoint="http://127.0.0.1:9")


@pytest.mark.parametrize("shape", FOREIGN_IDIOMS)
def test_result_without_verdict_key_fails_closed(adapter, shape):
    adapter._call_opa = lambda payload, timeout: shape
    with pytest.raises(PolicyUnavailableError):
        adapter.check(agent_id="a", capability="payments.initiate_wire", arguments={})


def test_contract_shape_still_fires(adapter):
    adapter._call_opa = lambda payload, timeout: {
        "fired": True,
        "outcome": "block",
        "rule_id": "r1",
    }
    r = adapter.check(agent_id="a", capability="payments.initiate_wire", arguments={})
    assert r.fired and r.outcome == "block" and r.matched_rule_id == "r1"


def test_explicit_no_objection_still_passes(adapter):
    adapter._call_opa = lambda payload, timeout: {"fired": False}
    r = adapter.check(agent_id="a", capability="payments.initiate_wire", arguments={})
    assert r.fired is False
