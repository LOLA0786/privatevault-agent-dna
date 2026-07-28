"""Enforce the dependency boundary of independently implemented verifiers."""

from __future__ import annotations

import ast
import re
import sys
import tomllib
from pathlib import Path

INDEPENDENT_VERIFIERS = (Path("tools/verify_records.py"),)
AUTHORITY_CLI = Path("tools/pv_authority_cli.py")

REPOSITORY_IMPORT_ROOTS = {
    "agent_dna",
    "privatevault",
    "tests",
    "tools",
}

IMPORT_TO_DISTRIBUTION = {
    "nacl": "pynacl",
}


def _imported_roots(path: Path) -> set[str]:
    tree = ast.parse(
        path.read_text(encoding="utf-8"),
        filename=str(path),
    )
    roots: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(
                alias.name.split(".", 1)[0]
                for alias in node.names
            )
        elif (
            isinstance(node, ast.ImportFrom)
            and node.level == 0
            and node.module
        ):
            roots.add(node.module.split(".", 1)[0])

    return roots


def _declared_distributions() -> set[str]:
    project = tomllib.loads(
        Path("pyproject.toml").read_text(encoding="utf-8")
    )["project"]

    requirements = list(project.get("dependencies", []))
    for values in project.get("optional-dependencies", {}).values():
        requirements.extend(values)

    names: set[str] = set()
    for requirement in requirements:
        match = re.match(r"[A-Za-z0-9_.-]+", requirement)
        assert match, (
            f"cannot parse dependency requirement {requirement!r}"
        )
        names.add(
            match.group().lower().replace("_", "-")
        )

    return names


def test_independent_verifiers_have_no_repository_imports() -> None:
    for path in INDEPENDENT_VERIFIERS:
        assert path.is_file(), (
            f"independent verifier missing: {path}"
        )

        leaked = (
            _imported_roots(path)
            & REPOSITORY_IMPORT_ROOTS
        )
        assert not leaked, (
            f"{path} imports repository modules: {sorted(leaked)}"
        )


def test_independent_verifier_dependencies_are_declared() -> None:
    declared = _declared_distributions()

    for path in INDEPENDENT_VERIFIERS:
        imported = _imported_roots(path)
        external = (
            imported
            - sys.stdlib_module_names
            - {"__future__"}
        )

        unknown = external - IMPORT_TO_DISTRIBUTION.keys()
        assert not unknown, (
            f"{path} has unmapped external imports: "
            f"{sorted(unknown)}"
        )

        undeclared = {
            root: IMPORT_TO_DISTRIBUTION[root]
            for root in external
            if IMPORT_TO_DISTRIBUTION[root] not in declared
        }
        assert not undeclared, (
            f"{path} has undeclared dependencies: {undeclared}"
        )


def test_authority_cli_is_explicitly_runtime_coupled() -> None:
    assert AUTHORITY_CLI not in INDEPENDENT_VERIFIERS
    assert "agent_dna" in _imported_roots(AUTHORITY_CLI)
