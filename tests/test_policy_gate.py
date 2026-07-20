"""Policy change gate: assertions, counterfactual, budgets, exit codes."""

import json

import pytest

from agent_dna.cli import EXIT_FAIL, EXIT_OK, EXIT_USAGE, main

RULE = {
    "policies": [{
        "id": "WIRE-CAP-200K",
        "capability": "payments.initiate_wire",
        "outcome": "block",
        "reason": "wires above 200k require manual release",
        "condition": {"field": "arguments.amount", "operator": ">",
                      "value": 200000},
    }],
    "assertions": [
        {"name": "blocks a 250k wire", "capability": "payments.initiate_wire",
         "arguments": {"amount": 250000}, "expect": "block"},
        {"name": "allows a 5k wire", "capability": "payments.initiate_wire",
         "arguments": {"amount": 5000}, "expect": "allow"},
    ],
}

CORPUS = [
    {"decision_id": "d-1", "agent_id": "ap-1",
     "capability": "payments.initiate_wire",
     "arguments": {"amount": 5000}, "decision": "allow"},
    {"decision_id": "d-2", "agent_id": "ap-1",
     "capability": "payments.initiate_wire",
     "arguments": {"amount": 250000}, "decision": "allow"},
    {"decision_id": "d-3", "agent_id": "ap-1",
     "capability": "crm.read_contact",
     "arguments": {}, "decision": "allow"},
]


def _files(tmp_path, rule=None, corpus=None):
    r = tmp_path / "rule.json"
    r.write_text(json.dumps(rule if rule is not None else RULE))
    f = tmp_path / "corpus.jsonl"
    f.write_text("\n".join(json.dumps(x) for x in
                           (corpus if corpus is not None else CORPUS)))
    return str(r), str(f)


def test_assertions_pass_and_gate_ok_within_budget(tmp_path, capsys):
    rule, fixture = _files(tmp_path)
    code = main(["policy", "check", "--rule", rule, "--fixture", fixture,
                 "--max-new-blocks", "1"])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "GATE: PASS" in out
    assert "would newly BLOCK    : 1" in out


def test_divergence_over_budget_fails_the_gate(tmp_path, capsys):
    rule, fixture = _files(tmp_path)
    code = main(["policy", "check", "--rule", rule, "--fixture", fixture])
    out = capsys.readouterr().out
    assert code == EXIT_FAIL
    assert "GATE: FAIL" in out
    assert "would newly BLOCK 1" in out


def test_failing_assertion_fails_the_gate(tmp_path, capsys):
    bad = json.loads(json.dumps(RULE))
    bad["assertions"][1]["expect"] = "block"   # 5k wire should NOT block
    rule, fixture = _files(tmp_path, rule=bad)
    code = main(["policy", "check", "--rule", rule, "--fixture", fixture,
                 "--max-new-blocks", "99"])
    out = capsys.readouterr().out
    assert code == EXIT_FAIL
    assert "assertion failed" in out
    assert "allows a 5k wire" in out


def test_rule_that_relaxes_enforcement_needs_acknowledgement(tmp_path, capsys):
    """A rule that newly ALLOWS a previously-refused decision is the
    scarier direction; budget defaults to 0."""
    corpus = [{"decision_id": "d-9", "agent_id": "a",
               "capability": "storage.bulk_export", "arguments": {},
               "decision": "block"}]
    rule = {"policies": [{"id": "NOOP", "capability": "payments.x",
                          "outcome": "block", "reason": "unrelated"}]}
    r, f = _files(tmp_path, rule=rule, corpus=corpus)
    code = main(["policy", "check", "--rule", r, "--fixture", f])
    out = capsys.readouterr().out
    assert code == EXIT_FAIL
    assert "newly ALLOW" in out


def test_sample_names_the_fired_rule_and_decision(tmp_path, capsys):
    rule, fixture = _files(tmp_path)
    main(["policy", "check", "--rule", rule, "--fixture", fixture,
          "--max-new-blocks", "5"])
    out = capsys.readouterr().out
    assert "d-2" in out and "payments.initiate_wire" in out
    assert "allow -> block" in out


def test_json_report_written_for_ci(tmp_path):
    rule, fixture = _files(tmp_path)
    report = tmp_path / "report.json"
    main(["policy", "check", "--rule", rule, "--fixture", fixture,
          "--max-new-blocks", "5", "--json", str(report)])
    data = json.loads(report.read_text())
    assert data["passed"] is True
    assert data["counterfactual"]["would_newly_block"] == 1
    assert all(a["passed"] for a in data["assertions"])


def test_missing_rule_file_is_usage_error(tmp_path, capsys):
    assert main(["policy", "check", "--rule",
                 str(tmp_path / "nope.json")]) == EXIT_USAGE


def test_history_db_requires_explicit_field_scope(tmp_path, capsys):
    rule, _ = _files(tmp_path)
    code = main(["policy", "check", "--rule", rule,
                 "--history-db", str(tmp_path / "pv.db")])
    err = capsys.readouterr().err
    assert code == EXIT_USAGE
    assert "field-scoped and opt-in" in err


def test_no_history_source_still_runs_assertions(tmp_path, capsys):
    rule, _ = _files(tmp_path)
    code = main(["policy", "check", "--rule", rule])
    out = capsys.readouterr().out
    assert code == EXIT_OK
    assert "counterfactual: skipped" in out
    assert "GATE: PASS" in out
