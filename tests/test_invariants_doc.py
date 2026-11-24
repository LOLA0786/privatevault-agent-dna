"""INVARIANTS.md stays short and true: numbered promises, at most ten, each
naming the tests that enforce it, and every test it names exists."""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "INVARIANTS.md"
PROMISE = re.compile(r"^## (\d+)\. (.+)$", re.M)
TEST_REF = re.compile(r"`(tests/[\w/.-]+\.py)(?:::(\w+))?`")


def _promises(text: str) -> list[tuple[str, str]]:
    heads = list(PROMISE.finditer(text))
    return [
        (
            m.group(2),
            text[m.end() : heads[i + 1].start() if i + 1 < len(heads) else len(text)],
        )
        for i, m in enumerate(heads)
    ]


def _defines(path: Path, name: str) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return any(
        isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == name
        for node in ast.walk(tree)
    )


def missing_tests(text: str, root: Path = ROOT) -> list[str]:
    out = []
    for path, name in TEST_REF.findall(text):
        target = root / path
        if not target.is_file():
            out.append(path)
        elif name and not _defines(target, name):
            out.append(f"{path}::{name}")
    return out


def test_promises_are_few_and_in_order():
    numbers = [int(n) for n, _ in PROMISE.findall(DOC.read_text(encoding="utf-8"))]
    assert numbers == list(range(1, len(numbers) + 1))
    assert 1 <= len(numbers) <= 10


def test_every_promise_names_its_tests():
    for title, body in _promises(DOC.read_text(encoding="utf-8")):
        assert "Enforced by:" in body and TEST_REF.search(body), title


def test_every_named_test_exists():
    assert missing_tests(DOC.read_text(encoding="utf-8")) == []


def test_negative_control_missing_test_is_caught(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_a.py").write_text("def test_real():\n    pass\n")
    text = (
        "## 1. X\n- Enforced by: `tests/test_a.py::test_real`, "
        "`tests/test_a.py::test_gone`, `tests/test_b.py`\n"
    )
    assert missing_tests(text, tmp_path) == [
        "tests/test_a.py::test_gone",
        "tests/test_b.py",
    ]
