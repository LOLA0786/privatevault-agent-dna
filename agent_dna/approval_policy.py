"""Who must approve what: quorums and roles for human approvals (ADR 0031).

ADR 0020 let one signed approval satisfy REQUIRE_APPROVAL. A bank's dual
control needs more: two (or N) different people, holding the right roles,
none of them the requester. The operator writes that down in an approval
policy file (``PV_APPROVAL_POLICY_FILE``)::

    {
      "spec": "pv-approval-policy/0.1",
      "approvers": {
        "alice@bank.example": {"roles": ["treasury"]},
        "bob@bank.example":   {"roles": ["treasury", "controller"]},
        "chen@bank.example":  {"roles": ["controller"]}
      },
      "rules": [
        {"capability": "payments.pay_invoice", "min_approvals": 2,
         "roles": ["treasury", "controller"], "require": {"controller": 1}},
        {"capability": "payments.*", "min_approvals": 2,
         "roles": ["treasury", "controller"]}
      ],
      "default": {"min_approvals": 1, "roles": ["treasury", "controller"]}
    }

A rule applies to a capability by exact name, else by the longest
``prefix.*`` match, else ``default``; without a default, an approval for an
unlisted capability is refused. For the rule that applies:

- every approver must be listed and hold at least one of ``roles``;
- approvers are counted once each, by principal (case-folded), and no two
  approvals may come from the same person;
- there must be at least ``min_approvals`` of them;
- ``require`` names roles that must be covered by distinct people: one
  person holding two roles fills one slot, never two.

Approver identity is what the approver trust bundle binds: each approval is
signed by a key whose bundle entry names the principal
(``verify_approval_for_execution``). Roles come only from this file.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent_dna.identity import fold_agent_id

APPROVAL_POLICY_SPEC = "pv-approval-policy/0.1"
MAX_APPROVALS = 10


class ApprovalPolicyError(ValueError):
    """The approval policy file is missing, unreadable or malformed."""


@dataclass(frozen=True)
class ApprovalRule:
    selector: str  # capability, "prefix.*", or "default"
    min_approvals: int
    roles: frozenset[str]
    require: Mapping[str, int]


@dataclass(frozen=True)
class QuorumResult:
    ok: bool
    detail: str
    rule: str | None = None


def _rule(raw: Any, selector: str) -> ApprovalRule:
    where = f"rule {selector!r}"
    if not isinstance(raw, Mapping):
        raise ApprovalPolicyError(f"{where}: must be an object")
    allowed = {"capability", "min_approvals", "roles", "require"}
    if set(raw) - allowed:
        raise ApprovalPolicyError(
            f"{where}: unknown fields {sorted(set(raw) - allowed)}"
        )
    n = raw.get("min_approvals")
    if isinstance(n, bool) or not isinstance(n, int) or not 1 <= n <= MAX_APPROVALS:
        raise ApprovalPolicyError(f"{where}: min_approvals must be 1..{MAX_APPROVALS}")
    roles = raw.get("roles")
    if (
        not isinstance(roles, list)
        or not roles
        or not all(isinstance(r, str) and r for r in roles)
    ):
        raise ApprovalPolicyError(f"{where}: roles must be a non-empty list of names")
    require = raw.get("require", {})
    if not isinstance(require, Mapping) or not all(
        isinstance(k, str) and isinstance(v, int) and not isinstance(v, bool) and v >= 1
        for k, v in require.items()
    ):
        raise ApprovalPolicyError(f"{where}: require maps role names to counts >= 1")
    if set(require) - set(roles):
        raise ApprovalPolicyError(
            f"{where}: required roles {sorted(set(require) - set(roles))} are not "
            "among the rule's roles"
        )
    if sum(require.values()) > n:
        raise ApprovalPolicyError(
            f"{where}: require asks for more distinct people than min_approvals"
        )
    return ApprovalRule(selector, n, frozenset(roles), dict(require))


class ApprovalPolicy:
    """A validated approval policy. ``digest`` is over the file's bytes."""

    def __init__(  # noqa: C901 - one refusal per malformed field
        self, document: Any, *, digest: str
    ) -> None:
        if not isinstance(document, Mapping):
            raise ApprovalPolicyError("approval policy must be a JSON object")
        if document.get("spec") != APPROVAL_POLICY_SPEC:
            raise ApprovalPolicyError(f"spec must be {APPROVAL_POLICY_SPEC!r}")
        if set(document) - {"spec", "approvers", "rules", "default"}:
            raise ApprovalPolicyError("unknown top-level fields")
        approvers = document.get("approvers")
        if not isinstance(approvers, Mapping) or not approvers:
            raise ApprovalPolicyError("approvers must be a non-empty object")
        self._roles: dict[str, frozenset[str]] = {}
        for principal, entry in approvers.items():
            folded = fold_agent_id(str(principal))
            if not principal or folded in self._roles:
                raise ApprovalPolicyError(
                    f"approver {principal!r} is empty or repeated"
                )
            roles = entry.get("roles") if isinstance(entry, Mapping) else None
            if (
                not isinstance(roles, list)
                or not roles
                or not all(isinstance(r, str) and r for r in roles)
            ):
                raise ApprovalPolicyError(
                    f"approver {principal!r}: roles must be a list"
                )
            self._roles[folded] = frozenset(roles)
        rules = document.get("rules", [])
        if not isinstance(rules, list):
            raise ApprovalPolicyError("rules must be a list")
        self._rules: dict[str, ApprovalRule] = {}
        for raw in rules:
            selector = raw.get("capability") if isinstance(raw, Mapping) else None
            if not isinstance(selector, str) or not selector or selector == "default":
                raise ApprovalPolicyError("every rule names a capability")
            if "*" in selector and not (
                selector.endswith(".*") and "*" not in selector[:-2]
            ):
                raise ApprovalPolicyError(
                    f"{selector!r}: only a trailing .* is allowed"
                )
            if selector in self._rules:
                raise ApprovalPolicyError(f"{selector!r}: repeated rule")
            self._rules[selector] = _rule(raw, selector)
        default = document.get("default")
        self._default = None if default is None else _rule(default, "default")
        known = set().union(*self._roles.values())
        for rule in [
            *self._rules.values(),
            *([self._default] if self._default else []),
        ]:
            if not rule.roles & known:
                raise ApprovalPolicyError(
                    f"rule {rule.selector!r}: no listed approver holds any of its roles"
                )
        self.digest = digest

    @classmethod
    def load(cls, path: str | Path) -> ApprovalPolicy:
        try:
            data = Path(path).read_bytes()
        except OSError as exc:
            raise ApprovalPolicyError(f"cannot read {path}: {exc.strerror}") from exc
        try:
            document = json.loads(data)
        except ValueError as exc:
            raise ApprovalPolicyError(f"{path} is not JSON: {exc}") from exc
        return cls(document, digest="sha256:" + hashlib.sha256(data).hexdigest())

    def rule_for(self, capability: str) -> ApprovalRule | None:
        if capability in self._rules:
            return self._rules[capability]
        best: ApprovalRule | None = None
        for selector, rule in self._rules.items():
            prefix = selector[:-1]  # "payments." from "payments.*"
            if selector.endswith(".*") and capability.startswith(prefix):
                if best is None or len(selector) > len(best.selector):
                    best = rule
        return best or self._default

    def roles_of(self, principal: str) -> frozenset[str]:
        return self._roles.get(fold_agent_id(principal), frozenset())

    def evaluate(self, capability: str, principals: Sequence[str]) -> QuorumResult:
        """Do these approvers (one per approval) satisfy the capability's rule?"""
        rule = self.rule_for(capability)
        if rule is None:
            return QuorumResult(
                False, f"no approval rule covers {capability!r} and there is no default"
            )
        folded = [fold_agent_id(p) for p in principals]
        if len(set(folded)) != len(folded):
            return QuorumResult(
                False, "the same person approved more than once", rule.selector
            )
        eligible: list[frozenset[str]] = []
        for principal in principals:
            held = self.roles_of(principal) & rule.roles
            if not held:
                return QuorumResult(
                    False,
                    f"{principal} holds none of the roles {sorted(rule.roles)} "
                    f"that may approve {capability!r}",
                    rule.selector,
                )
            eligible.append(held)
        if len(principals) < rule.min_approvals:
            return QuorumResult(
                False,
                f"{len(principals)} of {rule.min_approvals} required approvals",
                rule.selector,
            )
        if not _covers(rule.require, eligible):
            wanted = ", ".join(f"{n} {r}" for r, n in sorted(rule.require.items()))
            return QuorumResult(
                False,
                f"the approvers do not cover {wanted} with distinct people",
                rule.selector,
            )
        return QuorumResult(
            True,
            f"{len(principals)} of {rule.min_approvals} under rule {rule.selector!r}",
            rule.selector,
        )


def _covers(require: Mapping[str, int], eligible: Iterable[frozenset[str]]) -> bool:
    """Can each required role slot be filled by a different approver?
    (Bipartite matching by augmenting paths; at most 10 approvers.)"""
    slots = [role for role, n in sorted(require.items()) for _ in range(n)]
    people = list(eligible)
    owner: list[int | None] = [None] * len(slots)

    def assign(person: int, seen: set[int]) -> bool:
        for s, role in enumerate(slots):
            if role in people[person] and s not in seen:
                seen.add(s)
                if owner[s] is None or assign(owner[s], seen):  # type: ignore[arg-type]
                    owner[s] = person
                    return True
        return False

    for person in range(len(people)):
        assign(person, set())
    return all(o is not None for o in owner)
