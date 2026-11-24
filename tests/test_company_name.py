"""The company is named one way everywhere, by its legal name:
Pentaprime Solutions, Inc., a Delaware corporation. Due diligence once found
it written three different ways across the repository."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEGAL_NAME = "Pentaprime Solutions, Inc."
MENTION = re.compile(r"penta\s*prime", re.IGNORECASE)
SKIP = {
    ".git",
    ".venv",
    "node_modules",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    ".run",
    ".challenger",
}
TEXT = {
    "",
    ".md",
    ".txt",
    ".html",
    ".py",
    ".toml",
    ".json",
    ".yml",
    ".yaml",
    ".cff",
    ".ts",
    ".rs",
}


def _files(root: Path) -> Iterator[Path]:
    """Tracked files in a git checkout; otherwise every file but build output."""
    listed = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, capture_output=True, check=False
    )
    if listed.returncode == 0 and listed.stdout:
        yield from (root / name for name in listed.stdout.decode().split("\0") if name)
        return
    for path in root.rglob("*"):
        parts = path.relative_to(root).parts
        if SKIP & set(parts) or any(part.endswith(".egg-info") for part in parts):
            continue
        yield path


def other_forms(root: Path) -> Iterator[str]:
    """Every mention of the company that is not its exact legal name."""
    for path in _files(root):
        if not path.is_file() or path.suffix not in TEXT:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for m in MENTION.finditer(text):
            written = text[m.start() : m.start() + len(LEGAL_NAME)]
            if written != LEGAL_NAME:
                yield f"{path.relative_to(root)}: {written!r}"


def test_the_company_has_one_name():
    assert list(other_forms(ROOT)) == []


def test_negative_control_another_form_is_caught(tmp_path):
    (tmp_path / "NOTICE.md").write_text("(c) " + "PENTA" + "PRIME SOLUTIONS , INC\n")
    assert len(list(other_forms(tmp_path))) == 1
