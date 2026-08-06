"""
Agent Harness Skill Adapter — connects skill.md / skills.json
to LocalPolicyAdapter without modifying existing code.

Reads harness-exported capability manifests and enforces
them as local policy rules.
"""

import json
from pathlib import Path
from typing import Any

from agent_dna.policy.checker import PolicyCheckResult

from .local import LocalPolicyAdapter


class SkillAdapter(LocalPolicyAdapter):
    """
    Extends LocalPolicyAdapter with agent harness skill import.
    Existing LocalPolicyAdapter logic untouched.
    """

    SKILL_FILE = "skills.json"

    def __init__(self, skill_dir: str = "skills", policy_dir: str = "profiles") -> None:
        # skills (harness capability manifests) live in their own tree,
        # separate from L2 policy files; the parent handles policy_dir.
        # profile_dir was referenced but never set -- this is the fix.
        super().__init__(policy_dir)
        self.skill_dir = Path(skill_dir)

    def load_skills(self, agent_id: str) -> dict[str, Any]:
        skill_path = Path(self.skill_dir) / agent_id / self.SKILL_FILE
        if not skill_path.exists():
            return {}
        loaded = json.loads(skill_path.read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise ValueError(f"skill manifest must be a JSON object: {skill_path}")
        return loaded

    def check(
        self,
        agent_id: str | None = None,
        capability: str | None = None,
        arguments: dict[str, Any] | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> PolicyCheckResult:
        skills = self.load_skills(agent_id) if agent_id else {}
        allowed = skills.get("allowed_capabilities", [])
        denied = skills.get("denied_capabilities", [])

        # Skill-based enforcement: capability must be declared in skills
        if denied and capability in denied:
            return PolicyCheckResult(
                fired=True,
                outcome="block",
                reason=f"skill_denied: {capability}",
            )

        # If agent has explicit skills manifest, require match
        if allowed:
            if capability not in allowed:
                return PolicyCheckResult(
                    fired=True,
                    outcome="block",
                    reason=f"skill_not_authorized: {capability}",
                )
            return PolicyCheckResult(
                fired=False,
                outcome="allow",
                reason="skill_authorized",
            )

        # Fallback to parent adapter (profiles/grants)
        return super().check(agent_id, capability, arguments, evidence)
