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


# "outcome" without "fired" used to normalize to fired=False, which the engine
# skips: {"outcome": "block"} let the action through (audit finding, core A).
@pytest.mark.parametrize(
    ("shape", "fired", "outcome"),
    [
        ({"outcome": "block"}, True, "block"),
        ({"outcome": "require_approval"}, True, "require_approval"),
        ({"outcome": "allow"}, False, "allow"),
        ({"fired": True}, True, "require_approval"),
        ({"fired": False}, False, "allow"),
        ({"fired": True, "outcome": "block"}, True, "block"),
    ],
)
def test_either_verdict_key_alone_is_read_the_strict_way(
    adapter, shape, fired, outcome
):
    adapter._call_opa = lambda payload, timeout: shape
    r = adapter.check(agent_id="a", capability="payments.initiate_wire", arguments={})
    assert (r.fired, r.outcome) == (fired, outcome)


@pytest.mark.parametrize(
    "shape",
    [
        {"fired": False, "outcome": "block"},
        {"fired": False, "outcome": "require_approval"},
        {"fired": True, "outcome": "allow"},
        {"outcome": "deny"},
        {"fired": "yes", "outcome": "block"},
        {"fired": 1},
    ],
)
def test_contradictory_or_unknown_verdicts_fail_closed(adapter, shape):
    adapter._call_opa = lambda payload, timeout: shape
    with pytest.raises(PolicyUnavailableError):
        adapter.check(agent_id="a", capability="payments.initiate_wire", arguments={})


def test_the_cache_keys_on_the_full_digest():
    cached = OPAPolicyAdapter(endpoint="http://127.0.0.1:9", cache_ttl=60)
    cached._call_opa = lambda payload, timeout: {"fired": False}
    cached.check(agent_id="a", capability="crm.read_contact", arguments={"id": 7})
    assert cached._cache and all(len(key) == 64 for key in cached._cache)


def test_the_auditors_poc_is_blocked_by_the_engine(adapter):
    """End to end: Rego answering {"outcome": "block"} must stop the action."""
    import time

    from agent_dna.advisory import AdvisorySignal, Severity
    from agent_dna.decision import Decision, DecisionEngine
    from agent_dna.trace import AgentAction

    class Calm:
        def score(self, action, prev_capability=None):
            return AdvisorySignal(
                agent_id=action.agent_id,
                capability=action.capability,
                drift_score=0.0,
                severity=Severity.INFO,
                reasons=[],
            )

    adapter._call_opa = lambda payload, timeout: {
        "outcome": "block",
        "reason": "wire over limit",
    }
    action = AgentAction(
        agent_id="a",
        capability="payments.initiate_wire",
        timestamp=time.time(),
        arguments={"amount": 10_000_000},
    )
    assert (
        DecisionEngine(scorer=Calm(), policy=adapter).decide(action).decision
        == Decision.BLOCK
    )
