"""One agent, one identity (ADR 0021, lineage PR 1).

Case and Unicode-compatibility variants of an agent id must not become a
second identity to the checks that compare identities: API key loading,
approval separation of duties, maker != checker, and cycle detection.
"""

from __future__ import annotations

import json

import pytest

from agent_dna.apikeys import ApiKeyRegistry, generate_key
from agent_dna.connector.cross_agent import CrossAgentConfig, CrossAgentEnforcer
from agent_dna.identity import (
    AgentIdentityError,
    fold_agent_id,
    identity_collisions,
    is_strict_ascii_agent_id,
    normalize_agent_id,
)
from agent_dna.multi_agent import InteractionEvent
from agent_dna.multi_agent.invariant_engine import InvariantEngine, Verdict
from agent_dna.multi_agent.runtime_validator import RuntimeValidator
from agent_dna.security.loop_discovery import LoopDecision, LoopPolicy, discover_loops
from tests.connector.test_cross_agent import MakerNotChecker
from tests.test_approval_bridge import (  # noqa: F401
    AGENT,
    APPROVAL_SEPARATION_OF_DUTIES,
    ORG,
    ApproverWorld,
    World,
    _execution_action,
)
from tests.test_loop_discovery import _event

# ---- the fold ----------------------------------------------------------


@pytest.mark.parametrize(
    "variant",
    [
        "Treasury-Agent",
        "TREASURY-AGENT",
        "ｔｒｅａｓｕｒｙ-ａｇｅｎｔ",  # fullwidth
        " treasury-agent ",
    ],
)
def test_variants_fold_to_one_identity(variant):
    assert fold_agent_id(variant) == "treasury-agent"


def test_strict_normalize_refuses_hidden_characters():
    for bad in ("agent​01", "agent‮01", "agent\x0001", " agent", ""):
        with pytest.raises(AgentIdentityError):
            normalize_agent_id(bad)
    assert normalize_agent_id("Agent-01") == "agent-01"


def test_strict_ascii_rejects_confusables():
    assert is_strict_ascii_agent_id("treasury-agent")
    assert not is_strict_ascii_agent_id("treasury-аgent")  # Cyrillic а
    assert not is_strict_ascii_agent_id("Treasury-Agent")


def test_collisions_ignore_repeated_same_name():
    assert identity_collisions(["alice", "alice", "bob"]) == []
    assert identity_collisions(["alice", "Alice", "bob"]) == [("Alice", "alice")]


# ---- API keys ----------------------------------------------------------


def test_key_file_with_colliding_names_refuses_to_load(tmp_path):
    a, b = generate_key("maker-1"), generate_key("Maker-1")
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({a["hash"]: a["name"], b["hash"]: b["name"]}))
    with pytest.raises(ValueError, match="collide"):
        ApiKeyRegistry(str(path))


def test_rotated_key_with_same_name_still_loads(tmp_path):
    a, b = generate_key("maker-1"), generate_key("maker-1")
    path = tmp_path / "keys.json"
    path.write_text(json.dumps({a["hash"]: a["name"], b["hash"]: b["name"]}))
    assert ApiKeyRegistry(str(path)).enabled


# ---- approval separation of duties -------------------------------------


def test_case_variant_of_requester_cannot_approve(tmp_path):
    w = World(tmp_path)
    ea = _execution_action()
    approval = w.approver.approve(ea, request_id="req-case-1")
    variant = w.approver.approver_principal.upper()
    result = w.decide(approval, ea, callers=(variant,))
    assert APPROVAL_SEPARATION_OF_DUTIES in result.reason


# ---- maker != checker (CABI) -------------------------------------------


def _enforcer() -> CrossAgentEnforcer:
    corpus = [
        InteractionEvent(
            execution_id="corpus-1",
            source="maker-1",
            target="payment_rail",
            source_role="maker",
            target_role="rail",
            timestamp=1.0,
            intent="payments.initiate_wire",
        ),
        InteractionEvent(
            execution_id="corpus-1",
            source="checker-1",
            target="payment_rail",
            source_role="checker",
            target_role="rail",
            timestamp=2.0,
            intent="payments.approve_wire",
        ),
    ]
    return CrossAgentEnforcer(
        RuntimeValidator.from_corpus(
            corpus, engine=InvariantEngine([MakerNotChecker()])
        ),
        CrossAgentConfig(
            agent_roles={"maker-1": "maker", "checker-1": "checker"},
            tool_targets={"payments": ("payment_rail", "rail")},
        ),
    )


@pytest.mark.parametrize("approver", ["maker-1", "MAKER-1", "ｍａｋｅｒ-1"])
def test_maker_cannot_approve_as_case_variant(approver):
    enforcer = _enforcer()
    enforcer.observe("exec-1", "maker-1", "payments.initiate_wire")
    verdict = enforcer.observe("exec-1", approver, "payments.approve_wire")
    assert verdict is not None and verdict.verdict is Verdict.BLOCK


def test_distinct_checker_still_allowed():
    enforcer = _enforcer()
    enforcer.observe("exec-1", "maker-1", "payments.initiate_wire")
    verdict = enforcer.observe("exec-1", "checker-1", "payments.approve_wire")
    assert verdict is None or verdict.verdict is not Verdict.BLOCK


# ---- loop discovery ----------------------------------------------------


def _cycle_with_case_variant():
    return [
        _event("e1", "agent-a", "agent-b", relation="DELEGATES"),
        _event("e2", "agent-b", "AGENT-A", relation="DELEGATES", second=1),
    ]


def test_case_variant_cycle_detected_when_normalizing():
    report = discover_loops(
        _cycle_with_case_variant(), LoopPolicy(normalize_agent_ids=True)
    )
    assert report.decision is LoopDecision.BLOCK


def test_default_policy_unchanged_for_existing_reports():
    # normalization is opt-in on the library; /v1/authorize turns it on
    report = discover_loops(_cycle_with_case_variant())
    assert report.decision is not LoopDecision.BLOCK


def test_input_digest_covers_raw_events():
    raw = discover_loops(_cycle_with_case_variant())
    folded = discover_loops(
        _cycle_with_case_variant(), LoopPolicy(normalize_agent_ids=True)
    )
    assert raw.input_digest == folded.input_digest
