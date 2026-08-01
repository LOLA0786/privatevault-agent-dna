#!/usr/bin/env python3
"""pv scan -- read-only inventory of what agents in a log can do.

Reads a log file or a directory of them, reports every capability
observed, how much of it cannot be undone, and which agent reached the
most. Writes nothing, sends nothing, needs no credentials.

    pvscan ~/.claude/projects/
    pvscan agent.jsonl --json report.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

# --- BEGIN STANDALONE-STRIP ---
# Running as tools/pvscan.py puts tools/ on sys.path, not the repo root.
# The packaged pvscan.pyz carries agent_dna inside it and skips this.
_ROOT = Path(__file__).resolve().parent.parent
if (_ROOT / "agent_dna").is_dir() and str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

try:
    from agent_dna.scan import FORMATS, ingest
    from agent_dna.scan.inventory import EFFECTS, UNKNOWN, build_inventory
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "pvscan: cannot import agent_dna. Run from the repository root, or\n"
        "        use the packaged pvscan.pyz which needs no install.\n"
    )
    raise SystemExit(2) from None
# --- END STANDALONE-STRIP ---

LOG_SUFFIXES = (".jsonl", ".json", ".log", ".ndjson", ".csv", ".tsv")
RECURSIVE_LOG_SUFFIXES = (".jsonl", ".log", ".ndjson")
RULE = "=" * 68
THIN = "-" * 68


def find_logs(target: Path, max_files: int) -> list[Path]:
    if target.is_file():
        return [target]
    if not target.is_dir():
        raise SystemExit(f"pvscan: no such file or directory: {target}")
    found = sorted(
        p for p in target.rglob("*")
        if p.is_file()
        and p.suffix.lower() in RECURSIVE_LOG_SUFFIXES
        and p.stat().st_size > 0
    )
    return found[:max_files]


class Totals:
    """Aggregate across many files without pretending they are one file."""

    def __init__(self) -> None:
        self.files_read = 0
        self.files_empty: list[str] = []
        self.lines = 0
        self.actions = 0
        self.skipped = 0
        self.skip_reasons: dict[str, int] = {}
        self.formats: dict[str, int] = {}
        self.tools: dict[str, object] = {}
        self.agents: dict[str, object] = {}
        self.span: tuple[float, float] | None = None
        self.reported_outcomes: dict[str, int] = {}

    def absorb(self, inv, result) -> None:
        self.files_read += 1
        self.lines += inv.lines_read
        self.actions += inv.actions
        self.skipped += len(result.skipped)
        self.formats[inv.source_format] = self.formats.get(inv.source_format, 0) + 1
        for reason, n in inv.skip_reasons.items():
            self.skip_reasons[reason] = self.skip_reasons.get(reason, 0) + n
        if inv.actions == 0:
            self.files_empty.append(inv.source_path)

        for action in result.actions:
            reported = action.context.get("reported_outcome", "not_reported")
            label = str(reported).strip().lower() or "not_reported"
            self.reported_outcomes[label] = self.reported_outcomes.get(label, 0) + 1

        for name, usage in inv.tools.items():
            existing = self.tools.get(name)
            if existing is None:
                self.tools[name] = usage
                continue
            existing.count += usage.count
            existing.agents |= usage.agents
            for effect, n in usage.effects.items():
                existing.effects[effect] += n
            for effect, note in usage.notes.items():
                existing.notes.setdefault(effect, note)
            if usage.basis == "command":
                existing.basis = "command"
            for example in usage.examples:
                if example not in existing.examples and len(existing.examples) < 3:
                    existing.examples.append(example)

        for aid, profile in inv.agents.items():
            existing = self.agents.get(aid)
            if existing is None:
                self.agents[aid] = profile
                continue
            existing.actions += profile.actions
            existing.capabilities |= profile.capabilities
            existing.irreversible += profile.irreversible
            existing.mutating += profile.mutating
            existing.unknown += profile.unknown
            existing.read_only += profile.read_only

        if inv.time_span:
            lo, hi = inv.time_span
            self.span = (lo, hi) if self.span is None else (
                min(self.span[0], lo), max(self.span[1], hi)
            )

    @property
    def coverage(self) -> float:
        total = self.actions + self.skipped
        return (self.actions / total) if total else 0.0

    def by_effect(self) -> dict[str, int]:
        counts = dict.fromkeys(EFFECTS, 0)
        for usage in self.tools.values():
            for effect, n in usage.effects.items():
                counts[effect] += n
        return counts


def _ts(value: float | None) -> str:
    if value is None:
        return "-"
    return datetime.fromtimestamp(value, UTC).strftime("%Y-%m-%d %H:%M UTC")


def render(t: Totals, target: Path, top_agents: int = 15) -> str:
    out: list[str] = []
    add = out.append

    add(RULE)
    add("pv scan -- AGENT ACTION INVENTORY")
    add(RULE)
    add(f"Source            {target}")
    fmt = ", ".join(f"{k} x{v}" for k, v in sorted(t.formats.items()))
    add(f"Files read        {t.files_read}   ({fmt or 'none'})")
    add(f"Lines             {t.lines}")
    add(f"Actions parsed    {t.actions}   coverage {t.coverage:.0%}")
    if t.span:
        add(f"Window            {_ts(t.span[0])}  ->  {_ts(t.span[1])}")
    add(f"Agents / sessions {len(t.agents)}")
    add(f"Distinct tools    {len(t.tools)}")
    if t.reported_outcomes:
        outcomes = ", ".join(
            f"{name} {count}"
            for name, count in sorted(t.reported_outcomes.items())
        )
        add(f"Source outcomes   {outcomes}")
        add("                  Source labels only; not execution proof.")
    add("")

    counts = t.by_effect()
    add("EFFECT DISTRIBUTION")
    add(THIN)
    for effect in EFFECTS:
        n = counts[effect]
        pct = (n / t.actions * 100) if t.actions else 0.0
        bar = "#" * int(pct / 2.5)
        add(f"  {effect:14} {n:6}  {pct:5.1f}%  {bar}")
    add("")

    add("TOOLS OBSERVED")
    add(THIN)
    ordered = sorted(
        t.tools.values(),
        key=lambda u: (EFFECTS.index(u.worst), -u.count),
    )
    for usage in ordered[:25]:
        add(f"  {usage.capability:22} x{usage.count:<5} {usage.worst}")
        add(f"      {usage.spread()}   ({usage.basis}) {usage.note}")
        for example in usage.examples:
            add(f"      e.g. {example[:80]}")
    add("")

    irreversible = [u for u in ordered if u.irreversible]
    add("IRREVERSIBLE ACTIONS")
    add(THIN)
    if not irreversible:
        add("  None observed in this window.")
    else:
        total = sum(u.irreversible for u in irreversible)
        add(
            f"  {total} observed attempt(s) classified irreversible if executed."
        )
        add("  This inventory does not prove dispatch or a real-world effect.")
        for usage in irreversible:
            who = ", ".join(sorted(usage.agents)[:3])
            add(f"    {usage.capability:20} x{usage.irreversible:<4} by {who}")
    add("")

    add("OBSERVED ATTEMPTS BY AGENT")
    add(THIN)
    ranked = sorted(
        t.agents.values(), key=lambda a: (-a.irreversible, -len(a.capabilities))
    )
    add(f"  {'agent / session':30} {'acts':>5} {'tools':>6} {'irrev':>6} {'unknown':>8}")
    for profile in ranked[:top_agents]:
        add(
            f"  {profile.agent_id[:30]:30} {profile.actions:5} "
            f"{len(profile.capabilities):6} {profile.irreversible:6} {profile.unknown:8}"
        )
    if len(ranked) > top_agents:
        rest = ranked[top_agents:]
        add(
            f"  ... and {len(rest)} more, {sum(1 for a in rest if a.irreversible)} "
            f"of which reached an irreversible action (full list in --json)"
        )
    add("")

    unknown_tools = [u for u in ordered if u.effects.get(UNKNOWN)]
    if unknown_tools:
        add("UNCLASSIFIED")
        add(THIN)
        add("  Not recognised, so not assumed safe. Worth a human look.")
        for usage in unknown_tools:
            add(f"    {usage.capability:22} x{usage.effects[UNKNOWN]}")
        add("")

    add("AUTHORITY EVIDENCE")
    add(THIN)
    add("  Not assessed by this dependency-free inventory command.")
    add("  Run `pv authority scan` with a pinned trust bundle to classify")
    add("  evidence as VERIFIED, INVALID, UNVERIFIABLE, or ABSENT.")
    add("")

    if t.skip_reasons:
        add("LINES NOT UNDERSTOOD")
        add(THIN)
        for reason, n in sorted(t.skip_reasons.items(), key=lambda kv: -kv[1]):
            add(f"    {n:6}  {reason}")
        add("")

    if t.files_empty:
        add(f"  {len(t.files_empty)} file(s) yielded no actions. First few:")
        for path in t.files_empty[:3]:
            add(f"    {path}")
        add("")

    add(RULE)
    add("Read-only. No data transmitted. Reports are written locally")
    add("only when requested.")
    add(RULE)
    return "\n".join(out)


def to_json(t: Totals, target: Path) -> dict:
    return {
        "spec": "pv-scan-inventory/0.1",
        "source": str(target),
        "files_read": t.files_read,
        "lines": t.lines,
        "actions": t.actions,
        "coverage": round(t.coverage, 4),
        "formats": t.formats,
        "window": [_ts(t.span[0]), _ts(t.span[1])] if t.span else None,
        "effects": t.by_effect(),
        "tools": [
            {
                "capability": u.capability,
                "count": u.count,
                "worst": u.worst,
                "effects": u.effects,
                "basis": u.basis,
                "agents": sorted(u.agents),
                "examples": u.examples,
            }
            for u in sorted(t.tools.values(), key=lambda u: (EFFECTS.index(u.worst), -u.count))
        ],
        "agents": [
            {
                "agent_id": a.agent_id,
                "actions": a.actions,
                "reach": len(a.capabilities),
                "irreversible": a.irreversible,
                "mutating": a.mutating,
                "unknown": a.unknown,
                "read_only": a.read_only,
            }
            for a in sorted(t.agents.values(), key=lambda a: -a.irreversible)
        ],
        "authority_evidence_assessed": False,
        "reported_outcomes": t.reported_outcomes,
        "skip_reasons": t.skip_reasons,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pvscan",
        description="Read-only inventory of what agents in a log can do.",
    )
    parser.add_argument("path", help="log file, or directory to search recursively")
    parser.add_argument("--format", default="auto", choices=FORMATS,
                        help="override log format detection")
    parser.add_argument("--json", metavar="OUT", help="also write a JSON report")
    parser.add_argument("--max-files", type=int, default=500,
                        help="stop after this many files (default 500)")
    parser.add_argument("--agent-id", default=None,
                        help="identity for logs that carry none")
    parser.add_argument("--top", type=int, default=15,
                        help="agents to list before summarising (default 15)")
    parser.add_argument("--dry-run", action="store_true",
                        help="list the files that would be read, then stop")
    args = parser.parse_args(argv)

    target = Path(args.path).expanduser()
    logs = find_logs(target, args.max_files)
    if not logs:
        print(f"pvscan: no log files found under {target}")
        return 1

    if args.dry_run:
        print(f"pvscan --dry-run: {len(logs)} file(s) would be read")
        for path in logs:
            print(f"  {path}")
        return 0

    totals = Totals()
    failures: list[tuple[Path, str]] = []
    for path in logs:
        try:
            result = ingest(path, args.format, agent_id=args.agent_id)
        except Exception as exc:  # a bad file must not kill the scan
            failures.append((path, f"{type(exc).__name__}: {exc}"))
            continue
        totals.absorb(build_inventory(result), result)

    print(render(totals, target, top_agents=args.top))

    if failures:
        print("FILES THAT COULD NOT BE READ")
        print(THIN)
        for path, why in failures[:10]:
            print(f"  {path}: {why}")
        print()

    if args.json:
        Path(args.json).write_text(
            json.dumps(to_json(totals, target), indent=2), encoding="utf-8"
        )
        print(f"JSON written to {args.json}")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:  # piped into head/less; not an error
        import os
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        raise SystemExit(0) from None
