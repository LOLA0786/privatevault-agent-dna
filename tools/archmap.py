#!/usr/bin/env python3
"""Architecture map generated from source. Stdlib only, deterministic.

    python tools/archmap.py          # regenerate docs/architecture/*
    python tools/archmap.py --check  # exit 1 if committed map is stale

Nodes are directories (agent_dna/<subpkg>, agent_dna core modules, api,
tools, experimental, examples). Edges are Python imports resolved from the
AST. Solid edge: at least one import runs at import time. Dashed edge:
only lazy imports (inside a function). Cycles are computed on import-time
edges only, because lazy imports cannot form an import-time cycle.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCAN = ("agent_dna", "api", "tools", "experimental", "examples")
SKIP = {"__pycache__", ".venv", "node_modules", "target", "build", "dist"}
OUT_DIR = ROOT / "docs" / "architecture"
OUT_JSON = OUT_DIR / "modules.json"
OUT_MD = OUT_DIR / "MAP.md"
RUST = "rust/pv_runtime (PyO3)"
CORE_ROOTS = ("agent_dna", "api")


def _files(root: Path):
    for base in SCAN:
        d = root / base
        if not d.is_dir():
            continue
        for p in sorted(d.rglob("*.py")):
            if not SKIP.intersection(p.relative_to(root).parts):
                yield p


def _modname(root: Path, p: Path) -> str:
    parts = list(p.relative_to(root).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _resolve_from(mod: str, is_pkg: bool, node: ast.ImportFrom) -> str | None:
    if node.level == 0:
        return node.module
    base = mod.split(".") if is_pkg else mod.split(".")[:-1]
    if node.level > 1:
        base = base[: len(base) - (node.level - 1)]
    tail = node.module.split(".") if node.module else []
    return ".".join(base + tail) or None


class _Imports(ast.NodeVisitor):
    def __init__(self, mod: str, is_pkg: bool):
        self.mod, self.is_pkg, self.depth = mod, is_pkg, 0
        self.found: list[tuple[str, str]] = []

    def _scoped(self, node):
        self.depth += 1
        self.generic_visit(node)
        self.depth -= 1

    def visit_FunctionDef(self, node):  # noqa: N802 (ast.NodeVisitor API)
        self._scoped(node)

    def visit_AsyncFunctionDef(self, node):  # noqa: N802
        self._scoped(node)

    def visit_Lambda(self, node):  # noqa: N802
        self._scoped(node)

    def _kind(self) -> str:
        return "lazy" if self.depth else "top"

    def visit_Import(self, node):  # noqa: N802
        for a in node.names:
            self.found.append((a.name, self._kind()))

    def visit_ImportFrom(self, node):  # noqa: N802
        base = _resolve_from(self.mod, self.is_pkg, node)
        if not base:
            return
        self.found.append((base, self._kind()))
        for a in node.names:
            if a.name != "*":
                self.found.append((f"{base}.{a.name}", self._kind()))


def _group(root: Path, mod: str) -> str:
    parts = mod.split(".")
    if parts[0] != "agent_dna":
        return parts[0]
    if len(parts) >= 2 and (root / "agent_dna" / parts[1]).is_dir():
        return f"agent_dna/{parts[1]}"
    return "agent_dna (core modules)"


def _internal(known: set[str], target: str) -> str | None:
    parts = target.split(".")
    for n in range(len(parts), 0, -1):
        cand = ".".join(parts[:n])
        if cand in known:
            return cand
    return None


class _Tarjan:
    """Strongly connected components; components of size > 1 are cycles."""

    def __init__(self, adj):
        self.adj, self.index, self.low = adj, {}, {}
        self.stack, self.on, self.out, self.i = [], set(), [], 0

    def run(self, nodes) -> list[list[str]]:
        for n in sorted(nodes):
            if n not in self.index:
                self._visit(n)
        return sorted(self.out)

    def _visit(self, v):
        self.index[v] = self.low[v] = self.i
        self.i += 1
        self.stack.append(v)
        self.on.add(v)
        for w in sorted(self.adj.get(v, ())):
            if w not in self.index:
                self._visit(w)
                self.low[v] = min(self.low[v], self.low[w])
            elif w in self.on:
                self.low[v] = min(self.low[v], self.index[w])
        if self.low[v] == self.index[v]:
            self._pop(v)

    def _pop(self, v):
        comp = []
        while True:
            w = self.stack.pop()
            self.on.discard(w)
            comp.append(w)
            if w == v:
                break
        if len(comp) > 1:
            self.out.append(sorted(comp))


def _scan(root: Path, known: set[str], m: str, p: Path):
    src = p.read_text(encoding="utf-8", errors="replace")
    info = {
        "group": _group(root, m),
        "path": p.relative_to(root).as_posix(),
    }
    try:
        tree = ast.parse(src)
    except SyntaxError:
        info["parse_error"] = True
        return info, [], False
    v = _Imports(m, p.name == "__init__.py")
    v.visit(tree)
    found, uses_rust = [], False
    for target, kind in v.found:
        if target.split(".")[0] == "pv_runtime":
            uses_rust = True
            continue
        d = _internal(known, target)
        if d and d != m:
            found.append((d, kind))
    return info, found, uses_rust


def _summarize(modules: dict, edges: dict, rust: set) -> dict:
    adj = defaultdict(set)
    fan_in, fan_out = defaultdict(int), defaultdict(int)
    for (s, d), k in edges.items():
        fan_out[s] += 1
        fan_in[d] += 1
        if k == "top":
            adj[s].add(d)
    violations = sorted(
        f"{s} -> {d} ({k})"
        for (s, d), k in edges.items()
        if s.split(".")[0] in CORE_ROOTS and d.split(".")[0] == "experimental"
    )
    return {
        "modules": modules,
        "edges": sorted([s, d, k] for (s, d), k in edges.items()),
        "rust_bridge": sorted(rust),
        "cycles": _Tarjan(adj).run(modules),
        "core_to_experimental": violations,
        "fan_in": dict(sorted(fan_in.items())),
        "fan_out": dict(sorted(fan_out.items())),
    }


def build(root: Path = ROOT) -> dict:
    paths = {_modname(root, p): p for p in _files(root)}
    known = set(paths)
    modules, edges, rust = {}, {}, set()
    for m, p in sorted(paths.items()):
        info, found, uses_rust = _scan(root, known, m, p)
        modules[m] = info
        if uses_rust:
            rust.add(m)
        for d, kind in found:
            prev = edges.get((m, d))
            edges[(m, d)] = "top" if "top" in (prev, kind) else "lazy"
    return _summarize(modules, edges, rust)


def _group_graph(g: dict):
    mods = g["modules"]
    stats = defaultdict(lambda: {"modules": 0})
    for m in mods.values():
        stats[m["group"]]["modules"] += 1
    ge = defaultdict(lambda: {"top": 0, "lazy": 0})
    for s, d, k in g["edges"]:
        a, b = mods[s]["group"], mods[d]["group"]
        if a != b:
            ge[(a, b)][k] += 1
    for m in g["rust_bridge"]:
        ge[(mods[m]["group"], RUST)]["top"] += 1
    return stats, ge


def _bullets(items, fmt) -> list[str]:
    return [fmt(x) for x in items] or ["None."]


def render_md(g: dict) -> str:
    stats, ge = _group_graph(g)
    names = sorted(set(stats) | ({RUST} if g["rust_bridge"] else set()))
    ids = {n: f"n{i}" for i, n in enumerate(names)}
    lines = [
        "# Architecture map (generated)",
        "",
        "<!-- GENERATED by tools/archmap.py. Do not edit. Regenerate: python tools/archmap.py -->",
        "",
        "Nodes are directories; numbers are module counts. "
        "Solid arrow: imported at import time. Dashed: only lazy imports "
        "(inside functions). Label: number of module-to-module imports.",
        "",
        "```mermaid",
        "flowchart LR",
    ]
    for n in names:
        label = n if n == RUST else f"{n}<br/>{stats[n]['modules']} modules"
        lines.append(f'  {ids[n]}["{label}"]')
    for (a, b), c in sorted(ge.items()):
        arrow = "-->" if c["top"] else "-.->"
        lines.append(f"  {ids[a]} {arrow}|{c['top'] + c['lazy']}| {ids[b]}")
    lines += [
        "```",
        "",
        "## Directories",
        "",
        "| Directory | Modules | Lines |",
        "|---|---:|---:|",
    ]
    for n in sorted(stats, key=lambda x: (-stats[x]["modules"], x)):
        lines.append(f"| `{n}` | {stats[n]['modules']} |")
    hubs = sorted(g["fan_in"].items(), key=lambda kv: (-kv[1], kv[0]))[:15]
    lines += [
        "",
        "## Hubs (highest fan-in: changes here ripple furthest)",
        "",
        "| Module | Imported by | Imports |",
        "|---|---:|---:|",
    ]
    lines += [f"| `{m}` | {n} | {g['fan_out'].get(m, 0)} |" for m, n in hubs]
    lines += ["", "## Import-time cycles", ""]
    lines += _bullets(g["cycles"], lambda c: "- " + " ↔ ".join(f"`{x}`" for x in c))
    lines += ["", "## Core → experimental imports", ""]
    lines += _bullets(g["core_to_experimental"], lambda v: f"- `{v}`")
    lines += ["", "## Rust bridge (modules importing `pv_runtime`)", ""]
    lines += _bullets(g["rust_bridge"], lambda m: f"- `{m}`")
    return "\n".join(lines) + "\n"


def render_json(g: dict) -> str:
    return json.dumps(g, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args(argv)
    g = build()
    outputs = ((OUT_JSON, render_json(g)), (OUT_MD, render_md(g)))
    if args.check:
        stale = [
            p
            for p, want in outputs
            if not p.exists() or p.read_text(encoding="utf-8") != want
        ]
        for p in stale:
            print(f"STALE: {p.relative_to(ROOT)} -- run: python tools/archmap.py")
        return 1 if stale else 0
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for p, text in outputs:
        p.write_text(text, encoding="utf-8")
    print(
        f"modules={len(g['modules'])} edges={len(g['edges'])} cycles={len(g['cycles'])} "
        f"core_to_experimental={len(g['core_to_experimental'])} rust_bridge={len(g['rust_bridge'])}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
