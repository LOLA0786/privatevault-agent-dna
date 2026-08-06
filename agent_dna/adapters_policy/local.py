"""LocalPolicyAdapter — a real, minimal filesystem policy source.

Loads every ``*.yaml`` / ``*.yml`` / ``*.json`` policy document from a
directory (sorted filename order, deterministic), evaluates them with
the same ``PolicyChecker`` the L2 precedence level uses, and returns
the first firing result. Same evidence-honesty discipline: rules whose
condition fields are absent are SKIPPED, never silently passed.

Fail-closed at load time: an unreadable or invalid policy file raises
immediately (loader attaches the filename); it never degrades to an
empty policy set.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agent_dna.policy.checker import PolicyChecker, PolicyCheckResult
from agent_dna.policy.loader import load_policy_file

POLICY_SUFFIXES = (".yaml", ".yml", ".json")


class LocalPolicyAdapter:
    def __init__(self, policy_dir: str | Path = "profiles") -> None:
        self.policy_dir = Path(policy_dir)
        if not self.policy_dir.is_dir():
            raise FileNotFoundError(f"policy directory not found: {self.policy_dir}")
        paths = sorted(
            p for p in self.policy_dir.iterdir() if p.suffix in POLICY_SUFFIXES
        )
        # load eagerly and loudly: a broken policy file must fail at
        # construction, not be discovered mid-enforcement
        self._checkers: list[tuple[str, PolicyChecker]] = [
            (p.name, PolicyChecker(load_policy_file(p))) for p in paths
        ]

    @property
    def sources(self) -> list[str]:
        return [name for name, _ in self._checkers]

    def check(
        self,
        agent_id: str | None = None,
        capability: str | None = None,
        arguments: dict[str, Any] | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> PolicyCheckResult:
        skipped: list[str] = []
        evaluated: list[str] = []
        not_matched: list[str] = []
        for name, checker in self._checkers:
            result = checker.check(
                agent_id=agent_id or "",
                capability=capability or "",
                arguments=arguments,
                evidence=evidence,
            )
            evaluated.extend(f"{name}:{r}" for r in result.rules_evaluated)
            skipped.extend(f"{name}:{r}" for r in result.rules_skipped)
            not_matched.extend(f"{name}:{r}" for r in result.rules_not_matched)
            if result.fired:
                return PolicyCheckResult(
                    fired=True,
                    matched_rule_id=f"{name}:{result.matched_rule_id}",
                    outcome=result.outcome,
                    reason=result.reason,
                    rules_evaluated=evaluated,
                    rules_skipped=skipped,
                    rules_not_matched=not_matched,
                )
        return PolicyCheckResult(
            fired=False,
            reason=f"no rule fired across {len(self._checkers)} policy file(s)",
            rules_evaluated=evaluated,
            rules_skipped=skipped,
            rules_not_matched=not_matched,
        )
