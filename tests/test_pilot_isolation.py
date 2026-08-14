"""The Fineract lab experiment is deletable.

Nothing in the product may know it exists. This file lives outside
tests/pilot/ so it survives `rm -rf pilot/ tests/pilot/ docs/pilot/`
and then passes trivially.

AST imports/identifiers stay the first check: a keyword scan of
agent_dna/apikeys.py would hit the module docstring's English use of
the word, which is not an import of this experiment. That is not
enough. String literals and packaging/CI files are the seams that
actually reverse the dependency.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_TREES = ("agent_dna", "api", "tools", "tests")
_SKIP_DIR_NAMES = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "node_modules",
        ".worktrees",
    }
)
_NAMES = frozenset({"pilot", "fineract", "seabaas"})
# `pilot` alone matches ordinary prose ("pilot deployment", "pilot scope")
# in apikeys.py and server.py. Path-anchor it. fineract/seabaas are
# unambiguous as bare words and stay as-is.
_TERM = re.compile(r"(?i)(pilot[/\\]fineract|tests[./\\]pilot|\bfineract\b|\bseabaas\b)")

# Allowlist is empty. Each candidate from the brief was opened:
# - pytest marker: registered in tests/pilot/conftest.py pytest_configure
#   (that tree is excluded; pyproject.toml has no markers table).
# - optional extra named pilot: pyproject.toml [project.optional-dependencies]
#   has only "dev" and "integrations".
# - CI job named pilot: .github/workflows/{ci,rust,policy-gate,codeql}.yml
#   have no such job.
_ALLOWLIST: frozenset[tuple[str, int, str]] = frozenset()


def _python_files() -> list[Path]:
    files: list[Path] = []
    excluded_pilot_tests = (_REPO / "tests" / "pilot").resolve()
    self_path = Path(__file__).resolve()
    for tree_name in _TREES:
        root = _REPO / tree_name
        if not root.is_dir():
            continue
        for path in root.rglob("*.py"):
            resolved = path.resolve()
            if resolved == self_path:
                continue
            if (
                excluded_pilot_tests in resolved.parents
                or resolved == excluded_pilot_tests
            ):
                continue
            if any(part in _SKIP_DIR_NAMES for part in resolved.parts):
                continue
            files.append(resolved)
    return files


def _imported_segments(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.update(alias.name.split("."))
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.update(node.module.split("."))
    return names


def _identifiers(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names.add(node.name)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, ast.alias):
            names.add(node.name.split(".")[0])
            if node.asname:
                names.add(node.asname)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif isinstance(node, ast.Global | ast.Nonlocal):
            names.update(node.names)
    return names


def _term_hits(text: str, start_lineno: int) -> list[tuple[int, str]]:
    hits: list[tuple[int, str]] = []
    for offset, line in enumerate(text.splitlines()):
        for match in _TERM.finditer(line):
            hits.append((start_lineno + offset, match.group(0).lower()))
    return hits


def _string_literal_hits(tree: ast.AST) -> list[tuple[int, str]]:
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            hits.extend(_term_hits(node.value, node.lineno))
    return hits


def _confirmed_non_python_files() -> list[Path]:
    """Only paths opened and confirmed present. Missing names are omitted."""
    files: list[Path] = []
    for relative in (
        "pyproject.toml",
        "Dockerfile",
        "deploy/platform/Dockerfile.dashboard",
    ):
        path = _REPO / relative
        if path.is_file():
            files.append(path)
    workflows = _REPO / ".github" / "workflows"
    if workflows.is_dir():
        files.extend(sorted(p for p in workflows.iterdir() if p.is_file()))
    return files


def _format_hit(path: Path, lineno: int, term: str) -> str:
    rel = path.relative_to(_REPO).as_posix()
    return f"{rel}:{lineno}: {term}"


def _is_allowlisted(path: Path, lineno: int, term: str) -> bool:
    rel = path.relative_to(_REPO).as_posix()
    return (rel, lineno, term.lower()) in _ALLOWLIST


def test_core_does_not_reference_pilot() -> None:
    """The Fineract pilot is deletable. Nothing in the product may know it exists."""
    hits: list[str] = []
    for path in _python_files():
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        found = (_imported_segments(tree) | _identifiers(tree)) & _NAMES
        if found:
            rel = path.relative_to(_REPO)
            hits.append(f"{rel}: {sorted(found)}")
    assert hits == []


def test_core_does_not_embed_pilot_in_literals_or_config() -> None:
    """String literals and packaging/CI files must not name the experiment."""
    hits: list[str] = []
    for path in _python_files():
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        for lineno, term in _string_literal_hits(tree):
            if not _is_allowlisted(path, lineno, term):
                hits.append(_format_hit(path, lineno, term))
    for path in _confirmed_non_python_files():
        text = path.read_text(encoding="utf-8")
        for lineno, term in _term_hits(text, 1):
            if not _is_allowlisted(path, lineno, term):
                hits.append(_format_hit(path, lineno, term))
    assert hits == [], "product references the deletable experiment:\n" + "\n".join(
        hits
    )
