"""
Policy change gate — make a rule change a reviewable, testable artifact.

The scariest operation in a regulated enterprise is a control change,
because nobody can answer "what will this break?" before it ships.
This turns that question into a CI check with an exit code.

A candidate rule is evaluated two ways:

  1. ASSERTIONS (policy-as-tested-code). The rule file may declare what
     it MUST do -- "this must block a 200k wire, must allow a 5k one".
     A rule that cannot state its own intent has no business gating
     payments. Assertions run with zero history and always execute.

  2. COUNTERFACTUAL. The rule is replayed against decision history --
     either a committed fixture corpus (CI, no production data) or a
     live replay store (staging/prod, opt-in field-scoped retention).
     Reports what the rule WOULD have changed, with record hashes.

The gate fails (non-zero exit) when an assertion fails or when
divergence exceeds the declared budget. Budgets are explicit: a change
that newly blocks 211 previously-approved payments is not wrong, but
it must be *acknowledged* -- --max-new-blocks makes someone type the
number.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class AssertionResult:
    name: str
    expected: str
    actual: str
    passed: bool
    rule_id: Optional[str] = None


@dataclass
class GateResult:
    assertions: List[AssertionResult] = field(default_factory=list)
    counterfactual: Optional[Dict[str, Any]] = None
    violations: List[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.violations

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passed": self.passed,
            "assertions": [vars(a) for a in self.assertions],
            "counterfactual": self.counterfactual,
            "violations": self.violations,
        }


def load_candidate(path: str):
    """Load a candidate policy file. Returns (checker, assertions).

    Assertions are OUR extension to the policy document; they are
    stripped before parsing so the rule set itself stays a plain,
    portable policy document."""
    from .policy.checker import PolicyChecker
    from .policy.schema import parse_policy_dict

    raw = json.loads(Path(path).read_text())
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: expected a policy document object")
    assertions = raw.pop("assertions", [])
    return PolicyChecker(parse_policy_dict(raw)), assertions


def run_assertions(checker, assertions: List[Dict]) -> List[AssertionResult]:
    results = []
    for i, a in enumerate(assertions):
        name = a.get("name", f"assertion #{i + 1}")
        expected = a.get("expect", "allow")
        try:
            pr = checker.check(
                agent_id=a.get("agent_id", "gate-assertion-agent"),
                capability=a["capability"],
                arguments=a.get("arguments", {}),
                evidence=a.get("evidence"),
            )
            actual = pr.outcome if getattr(pr, "fired", False) else "allow"
            rule_id = getattr(pr, "matched_rule_id", None)
        except KeyError as e:
            results.append(AssertionResult(
                name, expected, f"malformed assertion: missing {e}", False))
            continue
        except Exception as e:  # noqa: BLE001
            results.append(AssertionResult(
                name, expected, f"{type(e).__name__}: {e}", False))
            continue
        results.append(AssertionResult(
            name, expected, actual, actual == expected, rule_id))
    return results


def counterfactual_from_fixture(checker, fixture_path: str) -> Dict[str, Any]:
    """Replay against a COMMITTED corpus -- the CI mode.

    Each JSONL line: {decision_id, agent_id, capability, arguments,
    decision}. A team commits a representative corpus (scrubbed,
    reviewed, versioned) so the gate runs in a pull request with no
    access to production data at all."""
    rows = []
    for line in Path(fixture_path).read_text().splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))

    newly_blocked, newly_allowed, errors = [], [], 0
    by_cap: Dict[str, int] = {}

    for row in rows:
        try:
            pr = checker.check(
                agent_id=row.get("agent_id", "unknown"),
                capability=row["capability"],
                arguments=row.get("arguments", {}),
                evidence=row.get("evidence"),
            )
            shadow = pr.outcome if getattr(pr, "fired", False) else "allow"
            rule_id = getattr(pr, "matched_rule_id", None)
        except Exception:  # noqa: BLE001
            errors += 1
            continue

        live = row.get("decision", "allow")
        if shadow in ("block", "require_approval") and live == "allow":
            newly_blocked.append({**row, "shadow": shadow, "rule": rule_id})
            by_cap[row["capability"]] = by_cap.get(row["capability"], 0) + 1
        elif shadow == "allow" and live in ("block", "require_approval"):
            newly_allowed.append({**row, "shadow": shadow})

    return {
        "source": f"fixture:{fixture_path}",
        "replayed": len(rows),
        "would_newly_block": len(newly_blocked),
        "would_newly_allow": len(newly_allowed),
        "candidate_errors": errors,
        "unchanged": len(rows) - len(newly_blocked) - len(newly_allowed) - errors,
        "newly_blocked_by_capability": dict(
            sorted(by_cap.items(), key=lambda kv: -kv[1])),
        "sample_newly_blocked": [
            {"decision_id": r.get("decision_id"), "capability": r["capability"],
             "agent_id": r.get("agent_id"), "live": r.get("decision"),
             "shadow": r["shadow"], "rule": r["rule"]}
            for r in newly_blocked[:10]
        ],
    }


def counterfactual_from_store(checker, db_path: str, replay_db: str,
                              retain_fields: List[str],
                              since_ts: Optional[float] = None,
                              limit: Optional[int] = None) -> Dict[str, Any]:
    """Replay against sealed history via the opt-in replay sidecar."""
    from .policy_replay import PolicyReplay, ReplayInputStore
    from .sqlite_store import SQLiteDecisionStore

    store = ReplayInputStore(path=replay_db, retain_fields=retain_fields)
    report = PolicyReplay(
        store=store, decision_store=SQLiteDecisionStore(db_path),
    ).replay(checker, since_ts=since_ts, limit=limit)
    report["source"] = f"store:{db_path}"
    return report


def evaluate_budget(result: GateResult, *, max_new_blocks: Optional[int],
                    max_new_allows: int = 0) -> GateResult:
    for a in result.assertions:
        if not a.passed:
            result.violations.append(
                f"assertion failed: {a.name!r} expected {a.expected}, "
                f"got {a.actual}")

    cf = result.counterfactual
    if cf and cf.get("status") != "unavailable":
        nb = cf.get("would_newly_block", 0)
        na = cf.get("would_newly_allow", 0)
        if max_new_blocks is not None and nb > max_new_blocks:
            result.violations.append(
                f"would newly BLOCK {nb} previously-allowed decision(s), "
                f"budget is {max_new_blocks} -- raise --max-new-blocks to "
                "acknowledge, or narrow the rule")
        if na > max_new_allows:
            result.violations.append(
                f"would newly ALLOW {na} previously-refused decision(s), "
                f"budget is {max_new_allows} -- a rule that RELAXES "
                "enforcement needs explicit acknowledgement")
        if cf.get("candidate_errors", 0) > 0:
            result.violations.append(
                f"candidate policy raised {cf['candidate_errors']} error(s) "
                "during replay -- a rule that crashes cannot gate anything")
    return result
