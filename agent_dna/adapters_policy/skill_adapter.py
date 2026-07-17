"""
Agent Harness Skill Adapter — connects skill.md / skills.json
to LocalPolicyAdapter without modifying existing code.

Reads harness-exported capability manifests and enforces
them as local policy rules.
"""
import json
from pathlib import Path
from .local import LocalPolicyAdapter


class SkillAdapter(LocalPolicyAdapter):
    """
    Extends LocalPolicyAdapter with agent harness skill import.
    Existing LocalPolicyAdapter logic untouched.
    """
    SKILL_FILE = "skills.json"

    def load_skills(self, agent_id: str) -> dict:
        skill_path = Path(self.profile_dir) / agent_id / self.SKILL_FILE
        if not skill_path.exists():
            return {}
        return json.loads(skill_path.read_text())

    def check(self, agent_id: str = None, capability: str = None,
              arguments: dict = None, evidence: dict = None):
        skills = self.load_skills(agent_id) if agent_id else {}
        allowed = skills.get("allowed_capabilities", [])
        denied = skills.get("denied_capabilities", [])

        # Skill-based enforcement: capability must be declared in skills
        if denied and capability in denied:
            return type("PolicyResult", (),
                        {"fired": True, "outcome": "block",
                         "reason": f"skill_denied: {capability}"})()

        # If agent has explicit skills manifest, require match
        if allowed:
            if capability not in allowed:
                return type("PolicyResult", (),
                            {"fired": True, "outcome": "block",
                             "reason": f"skill_not_authorized: {capability}"})()
            return type("PolicyResult", (),
                        {"fired": False, "outcome": "allow",
                         "reason": "skill_authorized"})()

        # Fallback to parent adapter (profiles/grants)
        return super().check(agent_id, capability, arguments, evidence)
