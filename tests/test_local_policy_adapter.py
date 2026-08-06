"""LocalPolicyAdapter: real filesystem policy source (was a stub).
Deterministic file order, first firing rule wins, fail-closed loading,
evidence-honest skips, experimental shim warns."""

import pytest


def _write_policies(tmp_path):
    (tmp_path / "10-treasury.yaml").write_text(
        """
version: "1.0"
policies:
  - id: wire-cap
    capability: payments.transfer
    outcome: block
    reason: transfers above limit are blocked
    condition:
      field: arguments.amount
      operator: ">"
      value: 100000
"""
    )
    (tmp_path / "20-export.json").write_text(
        '{"version": "1.0", "policies": [{"id": "no-bulk", '
        '"capability": "storage.bulk_export", "outcome": '
        '"require_approval", "reason": "exports need approval"}]}'
    )
    return tmp_path


def test_first_firing_rule_wins_with_source_attribution(tmp_path):
    from agent_dna.adapters_policy.local import LocalPolicyAdapter

    a = LocalPolicyAdapter(_write_policies(tmp_path))
    assert a.sources == ["10-treasury.yaml", "20-export.json"]
    r = a.check(
        agent_id="t1", capability="payments.transfer", arguments={"amount": 250000}
    )
    assert r.fired and r.outcome == "block"
    assert r.matched_rule_id == "10-treasury.yaml:wire-cap"


def test_non_matching_action_does_not_fire(tmp_path):
    from agent_dna.adapters_policy.local import LocalPolicyAdapter

    a = LocalPolicyAdapter(_write_policies(tmp_path))
    r = a.check(agent_id="t1", capability="crm.read_contact")
    assert not r.fired


def test_missing_evidence_is_skipped_not_passed(tmp_path):
    from agent_dna.adapters_policy.local import LocalPolicyAdapter

    a = LocalPolicyAdapter(_write_policies(tmp_path))
    r = a.check(agent_id="t1", capability="payments.transfer", arguments={})
    assert not r.fired
    assert any("wire-cap" in s for s in r.rules_skipped)


def test_broken_policy_file_fails_at_construction(tmp_path):
    from agent_dna.adapters_policy.local import LocalPolicyAdapter

    _write_policies(tmp_path)
    (tmp_path / "30-broken.yaml").write_text("policies: [ {id: incomplete")
    with pytest.raises(ValueError, match="30-broken.yaml"):
        LocalPolicyAdapter(tmp_path)


def test_missing_directory_fails_loudly(tmp_path):
    from agent_dna.adapters_policy.local import LocalPolicyAdapter

    with pytest.raises(FileNotFoundError):
        LocalPolicyAdapter(tmp_path / "nope")


def test_git_bundle_shim_warns_deprecated():
    import importlib

    with pytest.warns(DeprecationWarning, match="EXPERIMENTAL"):
        import agent_dna.adapters_policy.git_bundle as gb

        importlib.reload(gb)
