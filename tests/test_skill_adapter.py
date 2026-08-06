"""SkillAdapter: harness capability manifests (skills.json) enforced
as policy.

Reproduced from an external release audit: the adapter read
self.profile_dir, which the parent LocalPolicyAdapter never sets (it
sets policy_dir) -- so any agent connecting a skill manifest hit
AttributeError. Now SkillAdapter owns a skill_dir. This is a live
harness-integration path (agents export skills.json), so it is tested
rather than removed.
"""

import json


def _manifest(tmp, agent_id, allowed, denied):
    d = tmp / "skills" / agent_id
    d.mkdir(parents=True)
    (d / "skills.json").write_text(
        json.dumps(
            {
                "agent_id": agent_id,
                "allowed_capabilities": allowed,
                "denied_capabilities": denied,
            }
        )
    )


def _adapter(tmp):
    from agent_dna.adapters_policy.skill_adapter import SkillAdapter

    # policy_dir must exist for the parent; point it at an empty profiles dir
    (tmp / "profiles").mkdir()
    return SkillAdapter(skill_dir=str(tmp / "skills"), policy_dir=str(tmp / "profiles"))


def test_skill_adapter_constructs_without_attribute_error(tmp_path):
    _manifest(tmp_path, "code-agent-01", ["git.read_repo"], ["deploy.production"])
    a = _adapter(tmp_path)
    assert a.load_skills("code-agent-01")["agent_id"] == "code-agent-01"


def test_denied_capability_blocks(tmp_path):
    _manifest(tmp_path, "code-agent-01", ["git.read_repo"], ["deploy.production"])
    a = _adapter(tmp_path)
    r = a.check(agent_id="code-agent-01", capability="deploy.production")
    assert r.fired and r.outcome == "block"


def test_authorized_capability_passes(tmp_path):
    _manifest(tmp_path, "code-agent-01", ["git.read_repo"], ["deploy.production"])
    a = _adapter(tmp_path)
    r = a.check(agent_id="code-agent-01", capability="git.read_repo")
    assert not r.fired


def test_missing_manifest_falls_through_to_parent(tmp_path):
    a = _adapter(tmp_path)  # no manifest written
    # unknown agent -> load_skills returns {} -> parent handles it
    r = a.check(agent_id="no-such-agent", capability="anything")
    assert r is not None
