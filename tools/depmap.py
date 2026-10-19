#!/usr/bin/env python3
"""Who depends on whom, inside the runtime core. Generated, never hand-edited.

    python tools/depmap.py          # regenerate docs/architecture/DEPENDENCIES.md
    python tools/depmap.py --check  # exit 1 if the committed file is stale

Reads the import graph that tools/archmap.py extracts from the source
(docs/architecture/modules.json) and arranges the core (agent_dna, api) in
responsibility layers. Every core module must match a layer rule below; a
new module that matches none stops generation, so the document cannot fall
behind the code. Imports from a lower layer to a higher one are listed, not
hidden. Stdlib only, deterministic.
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from collections import defaultdict
from fnmatch import fnmatch
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULES = ROOT / "docs" / "architecture" / "modules.json"
OUT = ROOT / "docs" / "architecture" / "DEPENDENCIES.md"

# Bottom to top. First matching rule wins; order inside a layer is irrelevant.
LAYERS: list[tuple[str, str, tuple[str, ...]]] = [
    (
        "L1",
        "Contracts and primitives",
        (
            "agent_dna.trace",
            "agent_dna.advisory",
            "agent_dna.amount",
            "agent_dna.identity",
            "agent_dna.authority_v01",
            "agent_dna.action_v01",
            "agent_dna.wire_serialization_v01",
            "agent_dna.dispatch_context_v01",
            "agent_dna.key_custody",
            "agent_dna.presenter_identity",
            "agent_dna.execution_record",
            "agent_dna.request_bounds",
            "agent_dna.evidence",
            "agent_dna.observability.*",
            "agent_dna.connector.models",
            "agent_dna.gateway.errors",
            "agent_dna.multi_agent.events",
            "agent_dna.multi_agent.base",
            "agent_dna.multi_agent.interaction_graph",
        ),
    ),
    (
        "L2",
        "Evidence: records, permits, signatures",
        (
            "agent_dna.decision_record",
            "agent_dna.decision_graph",
            "agent_dna.execution_v01",
            "agent_dna.dispatch_v01",
            "agent_dna.closure_v01",
            "agent_dna.approval_v01",
            "agent_dna.signer",
            "agent_dna.signer_python",
            "agent_dna.signer_bridge",
            "agent_dna.receiver.receipts",
            "agent_dna.receiver.permit_header",
            "agent_dna.revocation_list",
            "agent_dna.export_manifest",
            "agent_dna.authorize_binding",
        ),
    ),
    (
        "L3",
        "Ledgers: SQLite and PostgreSQL",
        (
            "agent_dna.decision_store",
            "agent_dna.sqlite_store",
            "agent_dna.pg_store",
            "agent_dna.pg_compat",
            "agent_dna.pg_shared_state",
            "agent_dna.grant_spend",
            "agent_dna.grant_revocation",
            "agent_dna.lineage",
            "agent_dna.profile_store",
            "agent_dna.store.*",
            "agent_dna.receiver.ledger",
            "agent_dna.policy_replay",
        ),
    ),
    (
        "L4",
        "Decision engine: the precedence ladder and what it consults",
        (
            "agent_dna.decision",
            "agent_dna.uaal_layer",
            "agent_dna.eav",
            "agent_dna.eav.*",
            "agent_dna.invariants",
            "agent_dna.invariant_engine",
            "agent_dna.policy",
            "agent_dna.policy.*",
            "agent_dna.adapters_policy",
            "agent_dna.adapters_policy.*",
            "agent_dna.consensus",
            "agent_dna.consensus.*",
            "agent_dna.authorization",
            "agent_dna.allowlist",
            "agent_dna.grants",
            "agent_dna.open_authorizer",
            "agent_dna.economics",
            "agent_dna.economics.*",
            "agent_dna.scorer",
            "agent_dna.manifold",
            "agent_dna.dynamics",
            "agent_dna.fingerprint",
            "agent_dna.similarity",
            "agent_dna.confidence",
            "agent_dna.rate",
            "agent_dna.timeline",
            "agent_dna.diff",
            "agent_dna.reference_policies",
            "agent_dna.change_management",
            "agent_dna.operation_registry",
            "agent_dna.permit_evidence",
            "agent_dna.validation",
            "agent_dna.validation.*",
            "agent_dna.intent_adapter",
            "agent_dna.adapters",
            "agent_dna.adapters_framework",
            "agent_dna.adapters_framework.*",
            "agent_dna.shell_guard",
            "agent_dna.governance",
            "agent_dna.governance.*",
            "agent_dna.multi_agent",
            "agent_dna.multi_agent.*",
            "agent_dna.security",
            "agent_dna.security.*",
            "agent_dna.control_posture",
            "agent_dna.policy_miner",
            "agent_dna.policy_gate",
            "agent_dna.shadow",
        ),
    ),
    (
        "L5",
        "Enforcement runtime: monitor, breaker, recorder, gates, sidecar",
        (
            "agent_dna.apikeys",
            "agent_dna.circuit_breaker",
            "agent_dna.runtime",
            "agent_dna.decision_recorder",
            "agent_dna.approval_bridge",
            "agent_dna.authority_deadline",
            "agent_dna.connector",
            "agent_dna.connector.*",
            "agent_dna.receiver",
            "agent_dna.receiver.*",
            "agent_dna.gateway",
            "agent_dna.gateway.*",
        ),
    ),
    (
        "L6",
        "Composition and entry points",
        (
            "agent_dna",
            "agent_dna.composition",
            "api.server",
            "agent_dna.cli",
            "agent_dna.audit_connector",
            "agent_dna.audit_connector.*",
            "agent_dna.mcp_public_verifier",
            "agent_dna.backup",
            "agent_dna.key_lifecycle",
            "agent_dna.scan",
            "agent_dna.scan.*",
            "agent_dna.discovery",
        ),
    ),
]

# Entry points that sit inside a lower package but start a process.
ENTRY_POINTS = ("agent_dna.gateway.__main__",)


def layer_of(module: str) -> str:
    if module in ENTRY_POINTS:
        return "L6"
    for key, _title, patterns in LAYERS:
        if any(module == p or fnmatch(module, p) for p in patterns):
            return key
    raise SystemExit(f"depmap: {module} matches no layer rule in tools/depmap.py")


def _summary(module: str) -> str:
    rel = Path(*module.split("."))
    path = ROOT / (str(rel) + ".py")
    if not path.is_file():
        path = ROOT / rel / "__init__.py"
    try:
        doc = ast.get_docstring(ast.parse(path.read_text(encoding="utf-8"))) or ""
    except (OSError, SyntaxError):
        doc = ""
    line = doc.strip().splitlines()[0] if doc.strip() else ""
    return line.replace("|", "\\|").rstrip(".")[:110]


def _is_core(module: str) -> bool:
    return module == "agent_dna" or module.startswith(("agent_dna.", "api."))


def _graph(
    core: list[str], layer: dict[str, str], edges: list
) -> tuple[dict, dict, set]:
    deps: dict[str, set[str]] = defaultdict(set)
    users: dict[str, set[str]] = defaultdict(set)
    lazy: set[tuple[str, str]] = set()
    for src, dst, kind in edges:
        if src in layer and dst in layer and src != dst:
            deps[src].add(dst)
            users[dst].add(src)
            if kind != "top":
                lazy.add((src, dst))
    return deps, users, lazy


def _layer_diagram(core: list[str], layer: dict[str, str], deps: dict) -> list[str]:
    order = [k for k, _, _ in LAYERS]
    rank = {k: i for i, k in enumerate(order)}
    between: dict[tuple[str, str], int] = defaultdict(int)
    for src in core:
        for dst in deps[src]:
            if layer[src] != layer[dst]:
                between[(layer[src], layer[dst])] += 1
    counts: dict[str, int] = defaultdict(int)
    for m in core:
        counts[layer[m]] += 1
    out = ["```mermaid", "flowchart BT"]
    out += [f'  {k}["{k} {title}<br/>{counts[k]} modules"]' for k, title, _ in LAYERS]
    pairs = sorted(between.items(), key=lambda kv: (rank[kv[0][0]], rank[kv[0][1]]))
    out += [f"  {a} -->|{n}| {b}" for (a, b), n in pairs if rank[b] < rank[a]]
    out += [
        f"  {a} -.->|{n} upward| {b}"
        for (a, b), n in sorted(between.items())
        if rank[b] > rank[a]
    ]
    return [*out, "```", ""]


def _layer_tables(
    core: list[str], layer: dict[str, str], deps: dict, users: dict
) -> list[str]:
    out: list[str] = []
    for key, title, _ in reversed(LAYERS):
        out += [
            f"## {key}: {title}",
            "",
            "| Module | What it is | Depends on (core) | Used by |",
            "|---|---|---|---|",
        ]
        for m in (m for m in core if layer[m] == key):
            d = ", ".join(f"`{x}`" for x in sorted(deps[m])) or "nothing in the core"
            u = sorted(users[m])
            more = ", ..." if len(u) > 5 else ""
            used = (
                f"{len(u)}: " + ", ".join(f"`{x}`" for x in u[:5]) + more
                if u
                else "none"
            )
            out.append(f"| `{m}` | {_summary(m)} | {d} | {used} |")
        out.append("")
    return out


def _upward(core: list[str], layer: dict[str, str], deps: dict, lazy: set) -> list[str]:
    rank = {k: i for i, (k, _, _) in enumerate(LAYERS)}
    rows = [
        f"| `{s}` ({layer[s]}) | `{d}` ({layer[d]}) | {'lazy' if (s, d) in lazy else 'import time'} |"
        for s in core
        for d in sorted(deps[s])
        if rank[layer[d]] > rank[layer[s]]
    ]
    out = ["## Imports that point up a layer", ""]
    if not rows:
        return [*out, "None.", ""]
    return [
        *out,
        "Each is a lower layer reaching into a higher one. Lazy ones run inside a",
        "function (no import-time cycle); top-level ones are candidates to move.",
        "",
        "| From | To | Kind |",
        "|---|---|---|",
        *rows,
        "",
    ]


def render() -> str:
    data = json.loads(MODULES.read_text(encoding="utf-8"))
    core = sorted(m for m in data["modules"] if _is_core(m))
    layer = {m: layer_of(m) for m in core}
    deps, users, lazy = _graph(core, layer, data["edges"])
    head = [
        "# Who depends on whom (generated)",
        "",
        "<!-- GENERATED by tools/depmap.py from docs/architecture/modules.json. "
        "Do not edit. Regenerate: python tools/archmap.py && python tools/depmap.py -->",
        "",
        "The runtime core (`agent_dna/`, `api/`) arranged in six responsibility layers,",
        "bottom to top. A module may use anything in its own layer or below. Arrows",
        "point from the importing layer to the imported one; the number is how many",
        "module-to-module imports cross that way. Imports that point *up* a layer are",
        "listed at the end. For directories outside the core (tools, examples,",
        "experimental) see [MAP.md](MAP.md).",
        "",
    ]
    body = (
        head
        + _layer_diagram(core, layer, deps)
        + _layer_tables(core, layer, deps, users)
        + _upward(core, layer, deps, lazy)
    )
    return "\n".join(body)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--check", action="store_true")
    args = p.parse_args(argv)
    text = render()
    if args.check:
        if not OUT.is_file() or OUT.read_text(encoding="utf-8") != text:
            print(f"STALE: {OUT.relative_to(ROOT)} -- run: python tools/depmap.py")
            return 1
        return 0
    OUT.write_text(text, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
