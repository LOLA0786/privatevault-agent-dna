"""The structured docs (docs/README.md, docs/architecture/) stay true.

Claims -> tests:
  - Every code reference in the architecture pages resolves to a real file
    and definition -> test_code_references_resolve
  - Every relative link resolves -> test_relative_links_resolve
  - Every HTTP route the API serves is in FLOWS.md -> test_every_route_is_documented
  - Every table the code creates is in DATA.md -> test_every_table_is_documented
  - Every tracked top-level directory is in REPO-MAP.md
    -> test_every_top_level_entry_is_mapped
  - Every document under docs/ is in the index -> test_every_doc_is_indexed
  - DEPENDENCIES.md equals what tools/depmap.py generates, and a module with
    no layer stops generation -> test_dependencies_page_is_fresh,
    test_unassigned_module_is_refused
  - No build output is tracked -> test_no_build_output_is_tracked
Each check has a negative control.
"""

from __future__ import annotations

import ast
import importlib.util
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from tests.test_architecture_doc import unresolved
from tests.test_pilot_isolation import _TERM as _DELETABLE

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
ARCH = DOCS / "architecture"
CHECKED = [
    ARCH / "README.md",
    ARCH / "REPO-MAP.md",
    ARCH / "FLOWS.md",
    ARCH / "DATA.md",
    ARCH / "TRUST-AND-KEYS.md",
    ARCH / "DEPLOYMENT.md",
    DOCS / "README.md",
]
LINK = re.compile(r"\]\(([^)#\s]+)(?:#[^)]*)?\)")
MERMAID = re.compile(r"```mermaid\n(\w+)")
DIAGRAMS = {"flowchart", "sequenceDiagram"}
TABLE = re.compile(r"CREATE TABLE IF NOT EXISTS (\w+)")
ROUTE_METHODS = {"get", "post", "put", "delete", "patch"}

_spec = importlib.util.spec_from_file_location("depmap", ROOT / "tools" / "depmap.py")
depmap = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(depmap)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _git_files() -> list[str]:
    if shutil.which("git") is None or not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    out = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    )
    return out.stdout.splitlines()


# ---- references, links, diagrams ---------------------------------------------


@pytest.mark.parametrize("page", CHECKED, ids=lambda p: str(p.relative_to(ROOT)))
def test_code_references_resolve(page):
    assert unresolved(_read(page)) == []


def broken_links(page: Path, text: str) -> list[str]:
    return sorted(
        target
        for target in LINK.findall(text)
        if "://" not in target and not (page.parent / target).exists()
    )


@pytest.mark.parametrize("page", CHECKED, ids=lambda p: str(p.relative_to(ROOT)))
def test_relative_links_resolve(page):
    assert broken_links(page, _read(page)) == []


@pytest.mark.parametrize("page", CHECKED, ids=lambda p: str(p.relative_to(ROOT)))
def test_diagrams_declare_a_known_type(page):
    kinds = MERMAID.findall(_read(page))
    assert set(kinds) <= DIAGRAMS


def test_pages_carry_diagrams():
    total = sum(len(MERMAID.findall(_read(p))) for p in CHECKED)
    assert total >= 15


def test_negative_control_broken_link_is_caught():
    assert broken_links(ARCH / "README.md", "[x](NOPE.md) [y](FLOWS.md)") == ["NOPE.md"]


# ---- routes ------------------------------------------------------------------


def served_routes(source: str) -> set[str]:
    routes = set()
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if (
                isinstance(dec, ast.Call)
                and isinstance(dec.func, ast.Attribute)
                and dec.func.attr in ROUTE_METHODS
                and isinstance(dec.func.value, ast.Name)
                and dec.func.value.id == "app"
                and dec.args
                and isinstance(dec.args[0], ast.Constant)
            ):
                routes.add(f"{dec.func.attr.upper()} {dec.args[0].value}")
    return routes


def undocumented_routes(source: str, doc: str) -> list[str]:
    return sorted(r for r in served_routes(source) if f"`{r}`" not in doc)


def test_every_route_is_documented():
    source = _read(ROOT / "api" / "server.py")
    assert len(served_routes(source)) >= 15
    assert undocumented_routes(source, _read(ARCH / "FLOWS.md")) == []


def test_negative_control_new_route_is_caught():
    source = '@app.post("/v1/new")\ndef new():\n    pass\n'
    assert undocumented_routes(source, _read(ARCH / "FLOWS.md")) == ["POST /v1/new"]


# ---- tables ------------------------------------------------------------------


def created_tables() -> set[str]:
    tables: set[str] = set()
    for path in (ROOT / "agent_dna").rglob("*.py"):
        tables.update(TABLE.findall(_read(path)))
    return tables


def undocumented_tables(tables: set[str], doc: str) -> list[str]:
    return sorted(t for t in tables if f"| `{t}` |" not in doc)


def test_every_table_is_documented():
    tables = created_tables()
    assert {"records", "envelopes", "receiver_receipts"} <= tables
    assert undocumented_tables(tables, _read(ARCH / "DATA.md")) == []


def test_negative_control_new_table_is_caught():
    assert undocumented_tables({"records", "brand_new"}, _read(ARCH / "DATA.md")) == [
        "brand_new"
    ]


# ---- repository map and docs index ---------------------------------------------


def unmapped(files: list[str], doc: str) -> list[str]:
    dirs = {f.split("/", 1)[0] for f in files if "/" in f}
    return sorted(d for d in dirs if f"`{d}/`" not in doc and not d.startswith("."))


def test_every_top_level_entry_is_mapped():
    assert unmapped(_git_files(), _read(ARCH / "REPO-MAP.md")) == []


def test_negative_control_new_directory_is_caught():
    doc = _read(ARCH / "REPO-MAP.md")
    assert unmapped(["agent_dna/x.py", "newdir/y.py"], doc) == ["newdir"]


def unindexed(docs_root: Path, index: str) -> list[str]:
    out = []
    for path in sorted(docs_root.rglob("*.md")):
        rel = path.relative_to(docs_root).as_posix()
        if rel == "README.md" or re.match(r"adr/\d{4}-", rel):
            continue  # the index itself; ADRs are listed in adr/README.md
        if _DELETABLE.search(rel):
            continue  # the deletable lab experiment; the product may not name it
        if f"]({rel})" not in index:
            out.append(rel)
    return out


def test_every_doc_is_indexed():
    assert unindexed(DOCS, _read(DOCS / "README.md")) == []


def test_negative_control_unindexed_doc_is_caught(tmp_path):
    (tmp_path / "NEW.md").write_text("# new\n")
    (tmp_path / "adr").mkdir()
    (tmp_path / "adr" / "0099-x.md").write_text("# adr\n")
    assert unindexed(tmp_path, "") == ["NEW.md"]


# ---- generated dependency page -------------------------------------------------


def test_dependencies_page_is_fresh():
    assert _read(ARCH / "DEPENDENCIES.md") == depmap.render(), (
        "stale: run python tools/archmap.py && python tools/depmap.py"
    )
    assert depmap.main(["--check"]) == 0


def test_every_layer_is_populated():
    text = _read(ARCH / "DEPENDENCIES.md")
    for key, _title, _patterns in depmap.LAYERS:
        assert f"## {key}: " in text


def test_unassigned_module_is_refused():
    with pytest.raises(SystemExit, match="matches no layer rule"):
        depmap.layer_of("agent_dna.no_such_area")


def test_entry_point_sits_on_top():
    assert depmap.layer_of("agent_dna.gateway.__main__") == "L6"
    assert depmap.layer_of("agent_dna.gateway.mediator") == "L5"


# ---- hygiene -----------------------------------------------------------------

BUILD_OUTPUT = re.compile(
    r"(^|/)__pycache__/|\.pyc$|(^|/)[^/]+\.egg-info/|^rust/target/"
)


def build_output(files: list[str]) -> list[str]:
    return [f for f in files if BUILD_OUTPUT.search(f)]


def test_no_build_output_is_tracked():
    assert build_output(_git_files()) == []


def test_negative_control_build_output_is_caught():
    files = ["rust/target/debug/x", "agent_dna/__pycache__/a.pyc", "rust/src/lib.rs"]
    assert build_output(files) == files[:2]
