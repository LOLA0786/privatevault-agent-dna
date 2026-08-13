#!/usr/bin/env python3
"""Generate architecture.html from AST imports and real test names.

Never hand-maintain the map. Source of truth is:

  * import statements under tests/ (ast, not grep)
  * functions and methods named test_* (including async def)
  * the module inventory under agent_dna/ and api/

The headline test count is pytest's collected count (parametrize
expands). AST test_* names are shown separately so the map does not
lie about either number.

Stage assignment is a documented longest-prefix map of known package
layout onto the enforcement spine. Modules that do not fit a spine
stage go to "other / supporting" — they are not forced.

Visual system: paper/ink tokens, mono labels, hairline rules. The
same token block is intended to be shared with tools/gen_test_index.py
when that generator exists.

Usage: python tools/gen_architecture.py
"""

from __future__ import annotations

import ast
import html
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = ROOT / "tests"
AGENT_DNA_DIR = ROOT / "agent_dna"
API_DIR = ROOT / "api"
OUTPUT = ROOT / "architecture.html"

INTERESTING_ROOTS = ("agent_dna", "api")
COLLECT_TIMEOUT_SEC = 8
COLLECTED_RE = re.compile(r"(\d+)\+? tests? collected")

# Ordered enforcement spine. Do not invent stages.
SPINE: tuple[str, ...] = (
    "identity",
    "invariants",
    "policy",
    "approval",
    "grants",
    "limits",
    "anomaly",
    "permit mint",
    "dispatch",
)
OTHER = "other / supporting"

# Longest prefix wins. A module matches prefix P when the import name
# is P or P.<child>. Unmatched modules land in OTHER.
#
# Mapping rationale (package layout, not wishful grouping):
#   identity     — API keys, fingerprints, profiles, signers, gateway
#                  session/credentials (who is speaking)
#   invariants   — behavioral/UAAL/EAV invariant engines
#   policy       — policy package, gates, adapters, governance, allowlist
#   approval     — approval_v01; dual_control is a two-party approval
#   grants       — GrantRegistry, grant store, open/deprecated authorizers
#   limits       — circuit breaker (hard ceiling). Rate/cost live in anomaly
#                  because those modules are detectors, not ceilings.
#   anomaly      — drift, rate, cost, discovery, shadow, similarity
#   permit mint  — execution authorization, authority receipts, binding,
#                  execution trust bundle (mint-side, not the wire send)
#   dispatch     — dispatch witness, connector adapters, gateway, framework
#                  adapters. execution_trust is more specific → permit mint.
STAGE_PREFIXES: tuple[tuple[str, str], ...] = (
    ("agent_dna.apikeys", "identity"),
    ("agent_dna.fingerprint", "identity"),
    ("agent_dna.profile_store", "identity"),
    ("agent_dna.key_lifecycle", "identity"),
    ("agent_dna.signer_python", "identity"),
    ("agent_dna.signer_bridge", "identity"),
    ("agent_dna.signer", "identity"),
    ("agent_dna.mcp_public_verifier", "identity"),
    ("agent_dna.gateway.credentials", "identity"),
    ("agent_dna.gateway.session", "identity"),
    ("agent_dna.invariants", "invariants"),
    ("agent_dna.invariant_engine", "invariants"),
    ("agent_dna.eav", "invariants"),
    ("agent_dna.uaal_layer", "invariants"),
    ("agent_dna.multi_agent.invariant_engine", "invariants"),
    ("agent_dna.policy_gate", "policy"),
    ("agent_dna.policy_miner", "policy"),
    ("agent_dna.policy_replay", "policy"),
    ("agent_dna.policy", "policy"),
    ("agent_dna.adapters_policy", "policy"),
    ("agent_dna.reference_policies", "policy"),
    ("agent_dna.governance", "policy"),
    ("agent_dna.allowlist", "policy"),
    ("agent_dna.approval_v01", "approval"),
    ("agent_dna.multi_agent.dual_control", "approval"),
    ("agent_dna.grants", "grants"),
    ("agent_dna.store", "grants"),
    ("agent_dna.authorization", "grants"),
    ("agent_dna.open_authorizer", "grants"),
    ("agent_dna.circuit_breaker", "limits"),
    ("agent_dna.scorer", "anomaly"),
    ("agent_dna.advisory", "anomaly"),
    ("agent_dna.confidence", "anomaly"),
    ("agent_dna.dynamics", "anomaly"),
    ("agent_dna.discovery", "anomaly"),
    ("agent_dna.security", "anomaly"),
    ("agent_dna.validation.drift", "anomaly"),
    ("agent_dna.similarity", "anomaly"),
    ("agent_dna.diff", "anomaly"),
    ("agent_dna.shadow", "anomaly"),
    ("agent_dna.manifold", "anomaly"),
    ("agent_dna.rate", "anomaly"),
    ("agent_dna.economics", "anomaly"),
    ("agent_dna.runtime", "anomaly"),
    ("agent_dna.execution_v01", "permit mint"),
    ("agent_dna.authority_v01", "permit mint"),
    ("agent_dna.action_v01", "permit mint"),
    ("agent_dna.closure_v01", "permit mint"),
    ("agent_dna.execution_record", "permit mint"),
    ("agent_dna.authorize_binding", "permit mint"),
    ("agent_dna.connector.adapters.execution_trust", "permit mint"),
    ("agent_dna.dispatch_v01", "dispatch"),
    ("agent_dna.dispatch_context_v01", "dispatch"),
    ("agent_dna.connector", "dispatch"),
    ("agent_dna.gateway", "dispatch"),
    ("agent_dna.adapters_framework", "dispatch"),
    ("agent_dna.adapters", "dispatch"),
)

# Paper/ink tokens shared with the generated test index.
CSS = """
:root {
  --paper: #f4efe6;
  --ink: #1c1916;
  --muted: #6f675e;
  --line: #d4cbbd;
  --hairline: 1px solid var(--line);
  --accent: #9a2e1f;
  --zero: #9a2e1f;
  --chip: #ebe4d8;
  --sans: "Iowan Old Style", Palatino, "Palatino Linotype", Georgia, serif;
  --mono: "SFMono-Regular", "IBM Plex Mono", ui-monospace, Menlo, Consolas, monospace;
}
* { box-sizing: border-box; }
html { background: var(--paper); }
body {
  margin: 0;
  color: var(--ink);
  background: var(--paper);
  font-family: var(--sans);
  font-size: 17px;
  line-height: 1.45;
}
a { color: inherit; }
header, main, footer { max-width: 1180px; margin: 0 auto; padding: 0 28px; }
header { padding-top: 36px; padding-bottom: 28px; border-bottom: var(--hairline); }
.kicker {
  margin: 0 0 8px;
  color: var(--muted);
  font: 700 11px/1 var(--mono);
  letter-spacing: .14em;
  text-transform: uppercase;
}
h1 {
  margin: 0;
  font-size: clamp(40px, 6vw, 72px);
  font-weight: 500;
  letter-spacing: -.04em;
  line-height: .95;
}
.lede { max-width: 640px; margin: 18px 0 0; color: var(--muted); font-size: 16px; }
.metrics {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  margin-top: 28px;
  border-top: var(--hairline);
  border-bottom: var(--hairline);
}
.metric { padding: 16px 18px 16px 0; border-right: var(--hairline); }
.metric:last-child { border-right: 0; padding-right: 0; }
.metric .kicker { margin-bottom: 6px; }
.metric b {
  display: block;
  font: 500 28px/1 var(--mono);
  letter-spacing: -.03em;
}
.metric span { display: block; margin-top: 6px; color: var(--muted); font: 12px/1.4 var(--mono); }
nav {
  display: flex;
  flex-wrap: wrap;
  gap: 18px;
  padding: 14px 0 0;
  font: 700 11px/1 var(--mono);
  letter-spacing: .12em;
  text-transform: uppercase;
}
nav a { text-decoration: none; border-bottom: var(--hairline); padding-bottom: 2px; }
nav a:hover { border-bottom-color: var(--ink); }
section { padding: 48px 0 12px; border-bottom: var(--hairline); }
h2 {
  margin: 0 0 8px;
  font-size: 28px;
  font-weight: 500;
  letter-spacing: -.03em;
}
.section-lede { margin: 0 0 24px; color: var(--muted); max-width: 720px; }
.spine { display: grid; gap: 0; }
.stage {
  display: grid;
  grid-template-columns: 52px 160px 1fr auto;
  gap: 16px;
  align-items: start;
  padding: 16px 0;
  border-top: var(--hairline);
}
.stage:first-child { border-top: 0; }
.stage-idx {
  font: 700 11px/1 var(--mono);
  letter-spacing: .12em;
  color: var(--muted);
  padding-top: 6px;
}
.stage-name { font-size: 20px; letter-spacing: -.02em; padding-top: 2px; }
.stage-count {
  text-align: right;
  font: 500 18px/1.2 var(--mono);
  white-space: nowrap;
}
.stage-count small { display: block; color: var(--muted); font-size: 11px; font-weight: 400; }
.mods { display: flex; flex-wrap: wrap; gap: 6px; }
.chip {
  display: inline-flex;
  gap: 8px;
  align-items: baseline;
  background: var(--chip);
  border: var(--hairline);
  padding: 4px 8px;
  font: 12px/1.3 var(--mono);
}
.chip b { font-weight: 600; }
.chip.zero { color: var(--zero); border-color: var(--zero); background: transparent; }
.other-wrap { margin-top: 28px; padding-top: 20px; border-top: var(--hairline); }
.invert {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 36px;
  align-items: start;
}
.rank { list-style: none; margin: 0; padding: 0; }
.rank li {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 12px;
  align-items: center;
  padding: 8px 0;
  border-bottom: var(--hairline);
  font: 13px/1.35 var(--mono);
}
.bar {
  display: block;
  height: 3px;
  margin-top: 6px;
  background: var(--ink);
}
.zero-col h2 { color: var(--zero); }
.cluster { margin: 0 0 22px; padding: 0 0 18px; border-bottom: var(--hairline); }
.cluster.isolated { border: 1px solid var(--ink); padding: 16px 18px 18px; }
.cluster h3 { margin: 0 0 8px; font-size: 16px; font-weight: 600; }
.files { margin: 0; padding: 0; list-style: none; }
.files li { padding: 4px 0; font: 13px/1.4 var(--mono); }
.doc { color: var(--muted); font-family: var(--sans); font-size: 14px; }
.cross { display: grid; gap: 10px; }
.cross-card {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 12px;
  padding: 14px 0;
  border-top: var(--hairline);
  border-left: 3px solid var(--accent);
  padding-left: 14px;
}
.stages-path { font: 12px/1.5 var(--mono); color: var(--accent); }
.unparsed {
  background: var(--ink);
  color: var(--paper);
  padding: 16px 18px;
  margin: 24px 0 0;
  font: 13px/1.45 var(--mono);
}
.unparsed h2 { color: var(--paper); font-size: 16px; }
footer {
  padding: 28px 28px 48px;
  color: var(--muted);
  font: 12px/1.5 var(--mono);
}
@media (max-width: 860px) {
  .metrics, .invert, .stage { grid-template-columns: 1fr; }
  .stage-count { text-align: left; }
  .metric { border-right: 0; border-bottom: var(--hairline); }
}
"""


@dataclass
class TestFile:
    rel: str
    docstring: str
    imports: set[str] = field(default_factory=set)
    tests: list[str] = field(default_factory=list)
    pytest_count: int = 0


@dataclass
class ModuleInfo:
    name: str
    rel: str | None
    importers: set[str] = field(default_factory=set)


@dataclass
class CollectResult:
    count: int
    per_file: dict[str, int]
    raw_last_line: str
    ok: bool
    error: str


def e(text: str) -> str:
    return html.escape(text, quote=True)


def is_interesting(mod: str) -> bool:
    return any(mod == root or mod.startswith(root + ".") for root in INTERESTING_ROOTS)


def stage_of(mod: str) -> str:
    best = OTHER
    best_len = -1
    for prefix, stage in STAGE_PREFIXES:
        if mod == prefix or mod.startswith(prefix + "."):
            if len(prefix) > best_len:
                best = stage
                best_len = len(prefix)
    return best


def walk_py(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    out: list[Path] = []
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        out.append(path)
    return out


def path_to_module(path: Path, package_root: Path, package_name: str) -> str:
    rel = path.relative_to(package_root)
    parts = list(rel.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts:
        return package_name
    return package_name + "." + ".".join(parts)


def first_line(doc: str | None) -> str:
    if not doc:
        return ""
    for line in doc.strip().splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def extract_tests(tree: ast.Module) -> list[str]:
    names: list[str] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("test_"):
                names.append(node.name)
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if item.name.startswith("test_"):
                        names.append(f"{node.name}.{item.name}")
    return names


def _alias_name(alias: ast.alias) -> str | None:
    if alias.name == "*":
        return "*"
    return alias.name.split(".")[0] if alias.name else None


def resolve_import_from(
    module: str | None,
    names: list[str],
    known: set[str],
    level: int,
) -> set[str]:
    found: set[str] = set()
    if level != 0 or not module or not is_interesting(module):
        return found
    unresolved = False
    if not names or names == ["*"]:
        found.add(module)
        return found
    for name in names:
        if name == "*":
            found.add(module)
            continue
        candidate = f"{module}.{name}"
        if candidate in known:
            found.add(candidate)
        else:
            unresolved = True
    if unresolved:
        found.add(module)
    return found


def extract_imports(tree: ast.AST, known: set[str]) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name and is_interesting(alias.name):
                    found.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            names = [n for n in (_alias_name(a) for a in node.names) if n]
            found |= resolve_import_from(node.module, names, known, node.level)
    return found


def parse_python(path: Path) -> tuple[ast.Module | None, str | None]:
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return None, f"{exc}"
    try:
        return ast.parse(source, filename=str(path)), None
    except SyntaxError as exc:
        loc = f"line {exc.lineno}" if exc.lineno else "unknown line"
        return None, f"SyntaxError {loc}: {exc.msg}"


def inventory_modules() -> tuple[dict[str, ModuleInfo], list[tuple[str, str]]]:
    modules: dict[str, ModuleInfo] = {}
    unparsed: list[tuple[str, str]] = []
    packages = ((AGENT_DNA_DIR, "agent_dna"), (API_DIR, "api"))
    for directory, name in packages:
        if not directory.is_dir():
            raise SystemExit(f"missing package directory: {directory}")
        for path in walk_py(directory):
            mod = path_to_module(path, directory, name)
            rel = str(path.relative_to(ROOT).as_posix())
            modules[mod] = ModuleInfo(name=mod, rel=rel)
            tree, err = parse_python(path)
            if err:
                unparsed.append((rel, err))
            del tree
    return modules, unparsed


def parse_tests(
    known: set[str],
) -> tuple[dict[str, TestFile], list[tuple[str, str]], int]:
    if not TESTS_DIR.is_dir():
        raise SystemExit(f"missing tests directory: {TESTS_DIR}")
    files: dict[str, TestFile] = {}
    unparsed: list[tuple[str, str]] = []
    ast_count = 0
    for path in walk_py(TESTS_DIR):
        rel = str(path.relative_to(ROOT).as_posix())
        tree, err = parse_python(path)
        if err or tree is None:
            unparsed.append((rel, err or "unparsed"))
            files[rel] = TestFile(rel=rel, docstring="", imports=set(), tests=[])
            continue
        tests = extract_tests(tree)
        ast_count += len(tests)
        files[rel] = TestFile(
            rel=rel,
            docstring=first_line(ast.get_docstring(tree)),
            imports=extract_imports(tree, known),
            tests=tests,
        )
    return files, unparsed, ast_count


def collect_pytest() -> CollectResult:
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=COLLECT_TIMEOUT_SEC,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )
    except FileNotFoundError:
        return CollectResult(0, {}, "", False, "python executable missing")
    except subprocess.TimeoutExpired:
        return CollectResult(
            0, {}, "", False, f"pytest collect exceeded {COLLECT_TIMEOUT_SEC}s"
        )
    text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    last = lines[-1] if lines else ""
    count: int | None = None
    for line in reversed(lines):
        match = COLLECTED_RE.search(line)
        if match:
            count = int(match.group(1))
            last = line
            break
    per_file: dict[str, int] = defaultdict(int)
    for line in lines:
        if "::" not in line:
            continue
        node = line.split()[0] if line.split() else line
        path = node.split("::", 1)[0]
        if path.startswith("tests/"):
            per_file[path] += 1
    if count is None:
        return CollectResult(
            0,
            dict(per_file),
            last,
            False,
            f"could not parse pytest collect output (exit {proc.returncode}): {last}",
        )
    return CollectResult(count, dict(per_file), last, True, "")


def attach_importers(
    modules: dict[str, ModuleInfo], tests: dict[str, TestFile]
) -> None:
    for test in tests.values():
        for mod in test.imports:
            info = modules.get(mod)
            if info is None:
                modules[mod] = ModuleInfo(name=mod, rel=None, importers={test.rel})
            else:
                info.importers.add(test.rel)


def file_pytest_count(test: TestFile, collected: CollectResult) -> int:
    if test.rel in collected.per_file:
        return collected.per_file[test.rel]
    return len(test.tests)


def cluster_key(imports: set[str]) -> tuple[str, ...]:
    return tuple(sorted(imports))


def render_unparsed(items: list[tuple[str, str]]) -> str:
    if items:
        rows = "".join(f"<div>{e(path)} — {e(err)}</div>" for path, err in items)
    else:
        rows = "<div>none</div>"
    return (
        f'<div class="unparsed" id="unparsed"><h2>Unparsed ({len(items)})</h2>'
        f"{rows}</div>"
    )


def render_spine(
    modules: dict[str, ModuleInfo],
    tests: dict[str, TestFile],
) -> str:
    by_stage: dict[str, list[ModuleInfo]] = {stage: [] for stage in SPINE}
    by_stage[OTHER] = []
    for info in modules.values():
        by_stage[stage_of(info.name)].append(info)

    parts = [
        '<section id="enforcement">',
        "<h2>Enforcement path</h2>",
        '<p class="section-lede">Ordered spine from identity to dispatch. '
        "Counts are pytest-collected tests in files that import a module "
        "assigned to the stage. Modules that do not fit stay in "
        "other / supporting.</p>",
        '<div class="spine">',
    ]
    for idx, stage in enumerate(SPINE, start=1):
        parts.append(_stage_row(idx, stage, by_stage[stage], tests))
    parts.append("</div>")
    parts.append('<div class="other-wrap">')
    parts.append(_stage_row(None, OTHER, by_stage[OTHER], tests))
    parts.append("</div></section>")
    return "".join(parts)


def _stage_row(
    idx: int | None,
    stage: str,
    infos: list[ModuleInfo],
    tests: dict[str, TestFile],
) -> str:
    infos = sorted(infos, key=lambda m: (-len(m.importers), m.name))
    files: set[str] = set()
    for info in infos:
        files |= info.importers
    pytest_n = sum(tests[rel].pytest_count for rel in files if rel in tests)
    chips = []
    if not infos:
        chips.append('<span class="chip">no modules assigned</span>')
    for info in infos:
        klass = "chip zero" if not info.importers else "chip"
        missing = "" if info.rel else " (file not found)"
        chips.append(
            f'<span class="{klass}"><span>{e(info.name)}{e(missing)}</span>'
            f"<b>{len(info.importers)}</b></span>"
        )
    index = "—" if idx is None else f"{idx:02d}"
    return (
        f'<div class="stage">'
        f'<div class="stage-idx">{index}</div>'
        f'<div class="stage-name">{e(stage)}</div>'
        f'<div class="mods">{"".join(chips)}</div>'
        f'<div class="stage-count">{pytest_n}'
        f"<small>{len(files)} files · {len(infos)} modules</small></div>"
        f"</div>"
    )


def render_inversion(modules: dict[str, ModuleInfo]) -> str:
    ranked = sorted(modules.values(), key=lambda m: (-len(m.importers), m.name))
    imported = [m for m in ranked if m.importers]
    zeros = [m for m in ranked if not m.importers]
    max_n = max((len(m.importers) for m in imported), default=1)
    load_rows = "".join(_rank_row(m, max_n, zero=False) for m in imported)
    zero_rows = "".join(_rank_row(m, 1, zero=True) for m in zeros)
    return (
        '<section id="coverage">'
        "<h2>Coverage inversion</h2>"
        '<p class="section-lede">Every agent_dna / api module, ranked by how '
        "many test files import it. Zero-import modules are the other half of "
        "the same view — not a footnote.</p>"
        '<div class="invert">'
        f"<div><h2>Load-bearing · {len(imported)}</h2>"
        f'<ol class="rank">{load_rows}</ol></div>'
        f'<div class="zero-col"><h2>Zero test-file imports · {len(zeros)}</h2>'
        f'<ol class="rank">{zero_rows}</ol></div>'
        "</div></section>"
    )


def _rank_row(info: ModuleInfo, max_n: int, zero: bool) -> str:
    n = len(info.importers)
    width = 0 if zero or max_n == 0 else max(4, int(100 * n / max_n))
    missing = "" if info.rel else " · file not found"
    path = info.rel or "unresolved import"
    bar = "" if zero else f'<span class="bar" style="width:{width}%"></span>'
    klass = ' class="zero"' if zero else ""
    return (
        f"<li{klass}><div>{e(info.name)}{e(missing)}"
        f'<div class="doc">{e(path)}</div>{bar}</div>'
        f"<b>{n}</b></li>"
    )


def render_clusters(tests: dict[str, TestFile]) -> str:
    groups: dict[tuple[str, ...], list[TestFile]] = defaultdict(list)
    for test in tests.values():
        groups[cluster_key(test.imports)].append(test)
    isolated_key: tuple[str, ...] = ()
    isolated = groups.pop(isolated_key, [])
    clustered = sorted(
        groups.items(),
        key=lambda item: (-len(item[1]), item[0]),
    )
    parts = [
        '<section id="clusters">',
        "<h2>Clusters</h2>",
        '<p class="section-lede">Test files grouped by identical '
        "agent_dna / api import sets. Files that import none of those "
        "modules are isolated spec / vector / schema tests.</p>",
    ]
    parts.append(_cluster_block(isolated, isolated=True, label=None))
    for key, files in clustered:
        parts.append(_cluster_block(files, isolated=False, label=key))
    parts.append("</section>")
    return "".join(parts)


def _cluster_block(
    files: list[TestFile], isolated: bool, label: tuple[str, ...] | None
) -> str:
    files = sorted(files, key=lambda t: t.rel)
    if isolated:
        title = (
            f"Isolated · spec / vector / schema · {len(files)} files "
            "(no agent_dna or api import)"
        )
        klass = "cluster isolated"
        deps = "These files exercise fixtures, vectors, or schemas without importing the runtime packages."
    else:
        title = f"{len(files)} files · {len(label or ())} shared modules"
        klass = "cluster"
        shown = list(label or ())
        preview = shown[:8]
        extra = "" if len(shown) <= 8 else f" · +{len(shown) - 8} more"
        deps = ", ".join(preview) + extra
    items = []
    for test in files:
        doc = f'<div class="doc">{e(test.docstring)}</div>' if test.docstring else ""
        items.append(
            f"<li>{e(test.rel)} · {test.pytest_count} collected · "
            f"{len(test.tests)} test_*{doc}</li>"
        )
    if not files:
        items.append("<li>none</li>")
    return (
        f'<div class="{klass}"><h3>{e(title)}</h3>'
        f'<div class="doc">{e(deps)}</div>'
        f'<ul class="files">{"".join(items)}</ul></div>'
    )


def render_cross(tests: dict[str, TestFile]) -> str:
    cards = []
    for test in sorted(tests.values(), key=lambda t: t.rel):
        stages = sorted(
            {stage_of(mod) for mod in test.imports} - {OTHER},
            key=lambda s: SPINE.index(s) if s in SPINE else 99,
        )
        if len(stages) < 2:
            continue
        path = " × ".join(stages)
        doc = f'<div class="doc">{e(test.docstring)}</div>' if test.docstring else ""
        cards.append(
            f'<div class="cross-card"><div>{e(test.rel)}{doc}'
            f'<div class="stages-path">{e(path)}</div></div>'
            f"<b>{test.pytest_count}</b></div>"
        )
    body = "".join(cards) if cards else '<p class="section-lede">None.</p>'
    return (
        '<section id="cross">'
        "<h2>Cross-layer edges</h2>"
        '<p class="section-lede">A single test file that imports modules from '
        "more than one enforcement stage. These are composition tests — "
        "visually distinct because they catch what per-stage checks cannot.</p>"
        f'<div class="cross">{body}</div></section>'
    )


def render_html(
    *,
    collected: CollectResult,
    ast_count: int,
    tests: dict[str, TestFile],
    modules: dict[str, ModuleInfo],
    unparsed: list[tuple[str, str]],
    elapsed: float,
) -> str:
    zero_n = sum(1 for m in modules.values() if not m.importers)
    headline = str(collected.count)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Architecture map — PrivateVault Agent DNA</title>
<style>{CSS}</style>
</head>
<body data-pytest-collected="{e(headline)}">
<header>
<p class="kicker">Generated map · do not hand-edit</p>
<h1>Architecture</h1>
<p class="lede">Structural map from AST imports under tests/ onto
<code>agent_dna</code> and <code>api</code>. The headline number is pytest
collected tests, including parametrize. AST <code>test_*</code> functions
are the unexpanded names.</p>
<div class="metrics">
  <div class="metric">
    <p class="kicker">pytest collected</p>
    <b id="pytest-collected">{e(headline)}</b>
    <span>{e(collected.raw_last_line)}</span>
  </div>
  <div class="metric">
    <p class="kicker">AST test_* names</p>
    <b>{ast_count}</b>
    <span>functions and methods, including async def</span>
  </div>
  <div class="metric">
    <p class="kicker">test files</p>
    <b>{len(tests)}</b>
    <span>{sum(1 for t in tests.values() if t.imports)} import runtime modules</span>
  </div>
  <div class="metric">
    <p class="kicker">modules</p>
    <b>{len(modules)}</b>
    <span>{zero_n} with zero test-file imports</span>
  </div>
</div>
<nav>
  <a href="#enforcement">Enforcement path</a>
  <a href="#coverage">Coverage inversion</a>
  <a href="#clusters">Clusters</a>
  <a href="#cross">Cross-layer edges</a>
</nav>
{render_unparsed(unparsed)}
</header>
<main>
{render_spine(modules, tests)}
{render_inversion(modules)}
{render_clusters(tests)}
{render_cross(tests)}
</main>
<footer>
Generated by tools/gen_architecture.py in {elapsed:.2f}s.
Stage mapping is a longest-prefix table in that file. Unmatched modules
are other / supporting. This file is gitignored.
</footer>
</body>
</html>
"""


def main() -> int:
    started = time.perf_counter()
    modules, unparsed_modules = inventory_modules()
    known = set(modules)
    tests, unparsed_tests, ast_count = parse_tests(known)
    collected = collect_pytest()
    attach_importers(modules, tests)
    for test in tests.values():
        test.pytest_count = file_pytest_count(test, collected)
    unparsed = unparsed_modules + unparsed_tests
    elapsed = time.perf_counter() - started
    OUTPUT.write_text(
        render_html(
            collected=collected,
            ast_count=ast_count,
            tests=tests,
            modules=modules,
            unparsed=unparsed,
            elapsed=elapsed,
        ),
        encoding="utf-8",
    )
    print(f"wrote {OUTPUT.relative_to(ROOT)}")
    print(f"pytest collected: {collected.count if collected.ok else 'FAIL'}")
    print(f"pytest last line: {collected.raw_last_line}")
    print(f"AST test_* names: {ast_count}")
    print(f"test files: {len(tests)}")
    print(f"modules: {len(modules)}")
    print(
        "zero-import modules: "
        f"{sum(1 for m in modules.values() if not m.importers)}"
    )
    print(f"unparsed: {len(unparsed)}")
    for path, err in unparsed:
        print(f"  {path}: {err}")
    print(f"runtime: {elapsed:.2f}s")
    if not collected.ok:
        print(f"error: {collected.error}", file=sys.stderr)
        return 1
    if elapsed > 10:
        print(f"error: generator took {elapsed:.2f}s (budget 10s)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
