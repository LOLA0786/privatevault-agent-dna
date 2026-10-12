"""A persona is a YAML file: identity, tool names, grants, policy rules,
approvers. It compiles to the two files the PrivateVault runtime consumes
(``PV_POLICY_FILE`` and ``PV_GRANTS_FILE``). No rule is evaluated here; the
authority stays in the engine.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

REQUIRED = (
    "name",
    "agent_id",
    "organisation_id",
    "tools",
    "grants",
    "policy",
    "approvers",
)


@dataclass(frozen=True)
class CompiledPolicy:
    policy_file: Path
    grants_file: Path


@dataclass(frozen=True)
class Persona:
    name: str
    agent_id: str
    organisation_id: str
    description: str
    tools: tuple[str, ...]
    grants: tuple[dict[str, Any], ...]
    policy: tuple[dict[str, Any], ...]
    approvers: tuple[dict[str, Any], ...]
    limits: dict[str, Any]
    path: Path

    def compile(self, run_dir: Path) -> CompiledPolicy:
        run_dir.mkdir(parents=True, exist_ok=True)
        policy_file = run_dir / "policy.yaml"
        policy_file.write_text(
            yaml.safe_dump(
                {"version": "1.0", "policies": [dict(rule) for rule in self.policy]},
                sort_keys=False,
            ),
            encoding="utf-8",
        )
        grants = []
        for grant in self.grants:
            entry: dict[str, Any] = {
                "agent_id": self.agent_id,
                "capability": grant["capability"],
                "granted_by": f"persona:{self.name}",
            }
            for key in ("budget", "expires_at"):
                if key in grant:
                    entry[key] = grant[key]
            grants.append(entry)
        grants_file = run_dir / "grants.json"
        grants_file.write_text(json.dumps(grants, indent=2), encoding="utf-8")
        return CompiledPolicy(policy_file=policy_file, grants_file=grants_file)


def load_persona(path: str | Path) -> Persona:
    path = Path(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: persona must be a mapping")
    missing = [key for key in REQUIRED if key not in raw]
    if missing:
        raise ValueError(f"{path}: persona is missing {missing}")
    for rule in raw["policy"]:
        for key in ("id", "capability", "outcome", "reason"):
            if key not in rule:
                raise ValueError(f"{path}: policy rule is missing {key!r}: {rule}")
        if rule["outcome"] not in {"block", "require_approval"}:
            raise ValueError(
                f"{path}: policy outcome must be block or require_approval"
            )
    if not raw["approvers"]:
        raise ValueError(f"{path}: at least one approver is required")
    return Persona(
        name=str(raw["name"]),
        agent_id=str(raw["agent_id"]),
        organisation_id=str(raw["organisation_id"]),
        description=str(raw.get("description", "")),
        tools=tuple(str(t) for t in raw["tools"]),
        grants=tuple(dict(g) for g in raw["grants"]),
        policy=tuple(dict(r) for r in raw["policy"]),
        approvers=tuple(dict(a) for a in raw["approvers"]),
        limits=dict(raw.get("limits", {})),
        path=path,
    )
