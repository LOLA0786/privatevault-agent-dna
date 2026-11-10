"""A customer-policy REQUIRE_APPROVAL is additive: it never makes an action
easier to run than it was without the rule.

Before 2026-11 the engine returned at the first level that fired. A policy
hold sits above consensus, authorization, economics and drift, and it is one
of the two holds an approval can lift, so a matching rule such as "large
payments need sign-off" hid everything under it and an approval then turned
the action into an ALLOW. Each test states the verdict without the rule and
requires the rule not to weaken it."""

import json

import pytest

from agent_dna.advisory import AdvisorySignal, Posture, Severity
from agent_dna.decision import Decision
from agent_dna.economics.cost_check import CostAnomalyChecker
from agent_dna.grants import GrantRegistry
from agent_dna.policy.checker import PolicyChecker
from agent_dna.policy.loader import load_policy_file
from tests.test_approval_bridge import AGENT, CAP, World, _execution_action


def _rule(tmp_path, outcome="require_approval"):
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {
                "version": "1.0",
                "policies": [
                    {
                        "id": "review-large",
                        "capability": CAP,
                        "outcome": outcome,
                        "reason": "large payment needs sign-off",
                        "condition": {
                            "field": "arguments.amount",
                            "operator": ">",
                            "value": 10000,
                        },
                    }
                ],
            }
        )
    )
    return PolicyChecker(load_policy_file(path))


class _HighDrift:
    def score(self, action, prev=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.99,
            severity=Severity.CRITICAL,
            components={},
            reasons=["far off baseline"],
            recommended_posture=Posture.LOG,
        )


def _granted(world):
    registry = GrantRegistry()
    registry.grant(agent_id=AGENT, capability=CAP, granted_by="ops")
    world.engine.authorizer = registry


def _approved(world, evidence=None):
    action = _execution_action()
    return world.engine.decide(
        world.action(),
        evidence=evidence,
        approval=world.approver.approve(action, request_id="req-inv-1"),
        approval_context=world.context(action),
    )


def test_rule_does_not_lift_the_secure_profile_ungranted_block(tmp_path, monkeypatch):
    monkeypatch.setenv("PV_SECURE_PROFILE", "1")
    world = World(tmp_path)
    assert _approved(world).decision is Decision.BLOCK

    world.engine.policy = _rule(tmp_path)
    result = _approved(world)
    assert result.decision is Decision.BLOCK
    assert result.triggered_by == "authorization"
    assert result.also_fired == ["policy"]
    assert "no grant exists" in result.reason
    assert result.approval_artifact_digest is None


def test_rule_does_not_make_a_drift_hold_approvable(tmp_path):
    world = World(tmp_path)
    _granted(world)
    world.engine.scorer = _HighDrift()
    without = _approved(world)
    assert without.decision is Decision.REQUIRE_APPROVAL
    assert without.triggered_by == "drift"

    world.engine.policy = _rule(tmp_path)
    result = _approved(world)
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert result.triggered_by == "policy"
    assert result.also_fired == ["drift"]
    assert "also held by drift" in result.reason
    assert "drift escalations are not satisfiable by an approval" in result.reason


def test_rule_does_not_make_an_economics_hold_approvable(tmp_path):
    world = World(tmp_path)
    _granted(world)
    world.engine.economics = CostAnomalyChecker()
    evidence = {
        "economics": {"estimated_cost_usd": 900.0, "historical_avg_cost_usd": 1.0}
    }
    assert _approved(world, evidence).triggered_by == "economics"

    world.engine.policy = _rule(tmp_path)
    result = _approved(world, evidence)
    assert result.decision is Decision.REQUIRE_APPROVAL
    assert result.also_fired == ["economics"]


def test_rule_over_a_plain_authorization_hold_stays_approvable(tmp_path):
    """Both holds are approvable, so one approval for this action lifts both
    (ADR 0020 is unchanged)."""
    world = World(tmp_path)
    world.engine.policy = _rule(tmp_path)
    held = world.engine.decide(world.action())
    assert held.decision is Decision.REQUIRE_APPROVAL
    assert held.triggered_by == "policy"
    assert held.also_fired == ["authorization"]

    result = _approved(world)
    assert result.decision is Decision.ALLOW, result.reason
    assert result.triggered_by == "approval"


def test_rule_alone_is_still_an_approvable_hold(tmp_path):
    world = World(tmp_path)
    _granted(world)
    world.engine.policy = _rule(tmp_path)
    held = world.engine.decide(world.action())
    assert held.triggered_by == "policy"
    assert held.also_fired == []
    assert _approved(world).decision is Decision.ALLOW


def test_policy_block_is_still_final_and_first(tmp_path):
    world = World(tmp_path)
    world.engine.scorer = _HighDrift()
    world.engine.policy = _rule(tmp_path, outcome="block")
    result = _approved(world)
    assert result.decision is Decision.BLOCK
    assert result.triggered_by == "policy"


@pytest.mark.parametrize("secure", ["0", "1"])
@pytest.mark.parametrize("granted", [False, True])
@pytest.mark.parametrize("drifting", [False, True])
@pytest.mark.parametrize("costly", [False, True])
def test_adding_the_rule_never_makes_the_verdict_more_permissive(
    tmp_path, monkeypatch, secure, granted, drifting, costly
):
    """The property, over every combination of the levels under policy."""
    monkeypatch.setenv("PV_SECURE_PROFILE", secure)
    rank = {Decision.ALLOW: 0, Decision.REQUIRE_APPROVAL: 1, Decision.BLOCK: 2}
    evidence = (
        {"economics": {"estimated_cost_usd": 900.0, "historical_avg_cost_usd": 1.0}}
        if costly
        else None
    )

    def verdict(with_rule, sub):
        sub.mkdir()
        world = World(sub)
        if granted:
            _granted(world)
        if drifting:
            world.engine.scorer = _HighDrift()
        world.engine.economics = CostAnomalyChecker()
        if with_rule:
            world.engine.policy = _rule(sub)
        return _approved(world, evidence).decision

    without = verdict(False, tmp_path / "without")
    with_rule = verdict(True, tmp_path / "with")
    assert rank[with_rule] >= rank[without], (without, with_rule)
