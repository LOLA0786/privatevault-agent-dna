"""PolicyChecker: data-driven rules, evidence-honest, first-match-wins,
data-driven outcome (block vs require_approval per rule)."""

import pytest

from agent_dna.policy import PolicyChecker, parse_policy_dict


def _doc(policies):
    return parse_policy_dict({"policies": policies})


def test_simple_threshold_rule_fires():
    doc = _doc([{
        "id": "large-wire", "capability": "payment.initiate_wire",
        "condition": {"field": "arguments.amount", "operator": ">", "value": 50000},
        "outcome": "require_approval", "reason": "large wire needs approval",
    }])
    checker = PolicyChecker(doc)
    result = checker.check("a1", "payment.initiate_wire",
                           arguments={"amount": 100000})
    assert result.fired
    assert result.outcome == "require_approval"
    assert result.matched_rule_id == "large-wire"


def test_rule_does_not_fire_below_threshold():
    doc = _doc([{
        "id": "large-wire", "capability": "payment.initiate_wire",
        "condition": {"field": "arguments.amount", "operator": ">", "value": 50000},
        "outcome": "require_approval", "reason": "large wire needs approval",
    }])
    checker = PolicyChecker(doc)
    result = checker.check("a1", "payment.initiate_wire",
                           arguments={"amount": 1000})
    assert not result.fired


def test_missing_field_skips_not_fails():
    """Evidence-honesty: a rule referencing a field that isn't
    supplied must be SKIPPED, never treated as matching or not."""
    doc = _doc([{
        "id": "needs-evidence", "capability": "payment.initiate_wire",
        "condition": {"field": "evidence.risk_score", "operator": ">", "value": 0.8},
        "outcome": "block", "reason": "high risk",
    }])
    checker = PolicyChecker(doc)
    result = checker.check("a1", "payment.initiate_wire", arguments={})
    assert not result.fired
    assert "needs-evidence" in result.rules_skipped
    assert "needs-evidence" not in result.rules_evaluated


def test_agent_scoped_rule_only_applies_to_named_agent():
    doc = _doc([{
        "id": "finance-no-export", "capability": "storage.bulk_export",
        "agent_id": "finance-agent",
        "outcome": "block", "reason": "finance-agent forbidden from bulk export",
    }])
    checker = PolicyChecker(doc)

    fires = checker.check("finance-agent", "storage.bulk_export")
    assert fires.fired
    assert fires.outcome == "block"

    doesnt = checker.check("other-agent", "storage.bulk_export")
    assert not doesnt.fired


def test_wildcard_capability_matches_anything():
    doc = _doc([{
        "id": "global-block", "capability": "*", "agent_id": "banned-agent",
        "outcome": "block", "reason": "agent is fully banned",
    }])
    checker = PolicyChecker(doc)
    result = checker.check("banned-agent", "anything.at.all")
    assert result.fired
    assert result.outcome == "block"


def test_first_matching_rule_wins_not_all():
    doc = _doc([
        {"id": "rule-a", "capability": "payment.pay",
         "outcome": "require_approval", "reason": "rule a"},
        {"id": "rule-b", "capability": "payment.pay",
         "outcome": "block", "reason": "rule b"},
    ])
    checker = PolicyChecker(doc)
    result = checker.check("a1", "payment.pay")
    assert result.matched_rule_id == "rule-a"
    assert result.outcome == "require_approval"


def test_no_matching_rule_does_not_fire():
    doc = _doc([{
        "id": "irrelevant", "capability": "email.send",
        "outcome": "block", "reason": "n/a",
    }])
    checker = PolicyChecker(doc)
    result = checker.check("a1", "payment.pay")
    assert not result.fired


def test_incomparable_types_skip_not_crash():
    """A rule comparing a string field with > against a number must
    not crash, and must not be silently treated as matching."""
    doc = _doc([{
        "id": "bad-compare", "capability": "payment.pay",
        "condition": {"field": "arguments.amount", "operator": ">", "value": 100},
        "outcome": "block", "reason": "n/a",
    }])
    checker = PolicyChecker(doc)
    result = checker.check("a1", "payment.pay",
                           arguments={"amount": "not-a-number"})
    assert not result.fired


def test_invalid_operator_rejected_at_parse_time():
    with pytest.raises(ValueError, match="invalid operator"):
        _doc([{
            "id": "bad", "capability": "x",
            "condition": {"field": "arguments.a", "operator": "??", "value": 1},
            "outcome": "block", "reason": "n/a",
        }])


def test_invalid_outcome_rejected_at_parse_time():
    with pytest.raises(ValueError, match="invalid outcome"):
        _doc([{"id": "bad", "capability": "x",
               "outcome": "explode", "reason": "n/a"}])


def test_missing_required_field_rejected_at_parse_time():
    with pytest.raises(ValueError, match="missing required field 'id'"):
        parse_policy_dict({"policies": [{"capability": "x", "outcome": "block", "reason": "n/a"}]})


def test_duplicate_ids_rejected():
    with pytest.raises(ValueError, match="duplicate policy IDs"):
        _doc([
            {"id": "dup", "capability": "a", "outcome": "block", "reason": "n/a"},
            {"id": "dup", "capability": "b", "outcome": "block", "reason": "n/a"},
        ])
