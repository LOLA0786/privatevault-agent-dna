"""ARCHITECTURE.md stays true: every code reference resolves to a real
definition, every named path exists, and the precedence table equals the
pinned contract."""

import ast
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "ARCHITECTURE.md"
CONTRACT = ROOT / "spec" / "contracts" / "precedence-order.json"
REF = re.compile(r"`([\w./-]+\.py)::([A-Za-z_][\w.]*)`")
PATH = re.compile(
    r"`((?:agent_dna|api|tools|spec|docs|tests|rust|experimental)/[\w./-]*)`"
)
ROW = re.compile(r"^\| (\d+) \| `(\w+)` \| (\w+) \| (\w+) \|", re.M)
DEFS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def _defines(path: Path, dotted: str) -> bool:
    scope = ast.parse(path.read_text(encoding="utf-8")).body
    for part in dotted.split("."):
        hit = next((n for n in scope if isinstance(n, DEFS) and n.name == part), None)
        if hit is None:
            return False
        scope = hit.body
    return True


def unresolved(text: str, root: Path = ROOT) -> list[str]:
    bad = [
        f"{p}::{n}"
        for p, n in REF.findall(text)
        if not (root / p).is_file() or not _defines(root / p, n)
    ]
    bad += [p for p in PATH.findall(text) if not (root / p).exists()]
    return sorted(set(bad))


def table(text: str) -> list[tuple]:
    block = text.split("<!-- precedence:begin -->")[1].split("<!-- precedence:end -->")[
        0
    ]
    return [(int(o), n, c, v) for o, n, c, v in ROW.findall(block)]


def contract_rows() -> list[tuple]:
    levels = json.loads(CONTRACT.read_text(encoding="utf-8"))["levels"]
    return [
        (x["order"], x["name"], x["class"], x["outcome_on_violation"]) for x in levels
    ]


TEXT = DOC.read_text(encoding="utf-8")


def test_every_code_reference_resolves():
    assert unresolved(TEXT) == []


def test_doc_is_substantive():
    assert len(REF.findall(TEXT)) >= 15


def test_precedence_table_equals_pinned_contract():
    assert table(TEXT) == contract_rows()


def test_negative_control_missing_method_is_caught():
    ref = "`agent_dna/decision.py::DecisionEngine.no_such_method`"
    assert unresolved(ref) == ["agent_dna/decision.py::DecisionEngine.no_such_method"]


def test_negative_control_missing_file_is_caught():
    assert unresolved("`agent_dna/no_such_file.py::f` and `tools/nope.py`") == [
        "agent_dna/no_such_file.py::f",
        "tools/nope.py",
    ]


def test_negative_control_reordered_table_is_caught():
    rows = contract_rows()
    rows[2], rows[3] = rows[3], rows[2]
    fake = "\n".join(f"| {o} | `{n}` | {c} | {v} | x |" for o, n, c, v in rows)
    assert (
        table(f"<!-- precedence:begin -->\n{fake}\n<!-- precedence:end -->")
        != contract_rows()
    )
