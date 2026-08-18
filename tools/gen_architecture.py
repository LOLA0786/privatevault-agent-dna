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

Visual system: dark industrial dashboard (meeting-room presentation).
Do not hand-edit architecture.html.

Usage: python tools/gen_architecture.py
       open architecture.html
"""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = ROOT / "tests"
AGENT_DNA_DIR = ROOT / "agent_dna"
API_DIR = ROOT / "api"
OUTPUT = ROOT / "architecture.html"

INTERESTING_ROOTS = ("agent_dna", "api")
COLLECT_TIMEOUT_SEC = 8
COLLECTED_RE = re.compile(r"(\d+)\+? tests? collected")
COLLECT_TIME_RE = re.compile(r"in ([0-9.]+)s")
TEMPLATE = Path(__file__).resolve().parent / "architecture_dashboard.template.html"
# Configurable until live pytest JSON is wired. Not measured by this generator.
CONFIGURED_PASS_RATE_PERCENT = 100

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


def collect_duration_seconds(raw_last_line: str) -> float | None:
    match = COLLECT_TIME_RE.search(raw_last_line)
    if not match:
        return None
    return float(match.group(1))


_CLUSTER_BY_IMPORTS: dict[tuple[str, ...], str] = {
    ("agent_dna.apikeys", "api.server"): "API identity",
    ("agent_dna.authority_v01",): "Authority",
    ("api.server",): "API server",
}


def _rels_under(rels: list[str], folder: str) -> bool:
    prefix = f"tests/{folder}/"
    return bool(rels) and all(rel.startswith(prefix) for rel in rels)


def cluster_label(files: list[TestFile], imports: tuple[str, ...]) -> str:
    rels = [t.rel for t in files]
    if not imports:
        return "Isolated spec / vector / schema"
    named = _CLUSTER_BY_IMPORTS.get(imports)
    if named:
        return named
    if _rels_under(rels, "gateway"):
        return "Gateway adversarial"
    if _rels_under(rels, "connector"):
        joined = " ".join(rels)
        if "cross_agent" in joined:
            return "Connector cross-agent"
        if "exact_byte" in joined or "sidecar_tls" in joined:
            return "Exact-byte / sidecar TLS"
        return "Connector"
    if all(
        m == "agent_dna.validation" or m.startswith("agent_dna.validation.")
        for m in imports
    ):
        return "Validation"
    blob = " ".join(imports)
    if "decision_record" in blob and "advisory" in blob:
        return "Decision-record family"
    if "approval_v01" in blob and "authority_v01" in blob:
        return "Approval × authority"
    return ""


def _module_entry(info: ModuleInfo) -> dict[str, object]:
    return {
        "name": info.name,
        "path": info.rel,
        "testFileImports": len(info.importers),
    }


def _stage_payload(
    stage: str,
    infos: list[ModuleInfo],
    tests: dict[str, TestFile],
) -> dict[str, object]:
    infos = sorted(infos, key=lambda m: (-len(m.importers), m.name))
    files: set[str] = set()
    for info in infos:
        files |= info.importers
    pytest_n = sum(tests[rel].pytest_count for rel in files if rel in tests)
    return {
        "id": stage,
        "tests": pytest_n,
        "files": len(files),
        "modules": [_module_entry(mod) for mod in infos],
        "moduleCount": len(infos),
        "zeroImportCount": sum(1 for mod in infos if not mod.importers),
    }


def build_payload(
    *,
    collected: CollectResult,
    ast_count: int,
    tests: dict[str, TestFile],
    modules: dict[str, ModuleInfo],
    unparsed: list[tuple[str, str]],
    elapsed: float,
) -> dict[str, object]:
    by_stage: dict[str, list[ModuleInfo]] = {stage: [] for stage in SPINE}
    by_stage[OTHER] = []
    for info in modules.values():
        by_stage[stage_of(info.name)].append(info)

    spine = [_stage_payload(stage, by_stage[stage], tests) for stage in SPINE]
    other = _stage_payload(OTHER, by_stage[OTHER], tests)

    spine_module_n = sum(int(row["moduleCount"]) for row in spine)
    spine_imported_n = sum(
        int(row["moduleCount"]) - int(row["zeroImportCount"]) for row in spine
    )

    ranked = sorted(modules.values(), key=lambda m: (-len(m.importers), m.name))
    load_bearing = [_module_entry(m) for m in ranked if m.importers]
    zeros = [_module_entry(m) for m in ranked if not m.importers]

    groups: dict[tuple[str, ...], list[TestFile]] = defaultdict(list)
    for test in tests.values():
        groups[cluster_key(test.imports)].append(test)

    clusters: list[dict[str, object]] = []
    isolated_files = groups.pop((), [])
    clusters.append(
        {
            "label": cluster_label(isolated_files, ()),
            "isolated": True,
            "imports": [],
            "files": [
                {
                    "path": t.rel,
                    "doc": t.docstring,
                    "collected": t.pytest_count,
                    "astNames": len(t.tests),
                }
                for t in sorted(isolated_files, key=lambda x: x.rel)
            ],
        }
    )
    for imports, files in sorted(
        groups.items(), key=lambda item: (-len(item[1]), item[0])
    ):
        clusters.append(
            {
                "label": cluster_label(files, imports),
                "isolated": False,
                "imports": list(imports),
                "files": [
                    {
                        "path": t.rel,
                        "doc": t.docstring,
                        "collected": t.pytest_count,
                        "astNames": len(t.tests),
                    }
                    for t in sorted(files, key=lambda x: x.rel)
                ],
            }
        )

    cross: list[dict[str, object]] = []
    for test in tests.values():
        stages = sorted(
            {stage_of(mod) for mod in test.imports} - {OTHER},
            key=lambda s: SPINE.index(s) if s in SPINE else 99,
        )
        if len(stages) < 2:
            continue
        cross.append(
            {
                "path": test.rel,
                "doc": test.docstring,
                "stages": stages,
                "collected": test.pytest_count,
            }
        )
    cross.sort(key=lambda row: (-int(row["collected"]), str(row["path"])))

    return {
        "generatedAt": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generatorSeconds": round(elapsed, 2),
        "pytest": {
            "collected": collected.count,
            "ok": collected.ok,
            "lastLine": collected.raw_last_line,
            "collectSeconds": collect_duration_seconds(collected.raw_last_line),
        },
        "suite": {
            "passRatePercent": CONFIGURED_PASS_RATE_PERCENT,
            "source": "configured",
            "note": "Pass rate is configured until live pytest JSON is wired. Not measured by this generator.",
        },
        "astTestNames": ast_count,
        "testFiles": len(tests),
        "modules": len(modules),
        "zeroImportModules": len(zeros),
        "spineCoverage": {
            "imported": spine_imported_n,
            "total": spine_module_n,
            "definition": "Spine modules imported by at least one test file, excluding other/supporting.",
        },
        "spine": spine,
        "other": other,
        "loadBearing": load_bearing,
        "zeroImports": zeros,
        "clusters": clusters,
        "crossLayer": cross,
        "unparsed": [{"path": path, "error": err} for path, err in unparsed],
    }


def render_html(
    *,
    collected: CollectResult,
    ast_count: int,
    tests: dict[str, TestFile],
    modules: dict[str, ModuleInfo],
    unparsed: list[tuple[str, str]],
    elapsed: float,
) -> str:
    if not TEMPLATE.is_file():
        raise SystemExit(f"missing dashboard template: {TEMPLATE}")
    payload = build_payload(
        collected=collected,
        ast_count=ast_count,
        tests=tests,
        modules=modules,
        unparsed=unparsed,
        elapsed=elapsed,
    )
    template = TEMPLATE.read_text(encoding="utf-8")
    if "__DATA_JSON__" not in template:
        raise SystemExit("dashboard template missing __DATA_JSON__ placeholder")
    data_json = json.dumps(payload, indent=2).replace("<", "\\u003c")
    html_out = template.replace("__DATA_JSON__", data_json)
    html_out = html_out.replace(
        "__PYTEST_COLLECTED__", str(collected.count if collected.ok else 0)
    )
    return html_out


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
    print(f"zero-import modules: {sum(1 for m in modules.values() if not m.importers)}")
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
