"""What the agents in a log can actually do.

The authority half of a scan asks whether an action was permitted. This
half asks a prior question the operator can answer today: what is in the
log at all, and how much of it cannot be undone.

Classification is by capability name and, for shell-like tools, by the
command itself. It is deliberately conservative in one direction only:
a capability we do not recognise is UNKNOWN, never READ_ONLY. Assuming
an unrecognised tool is harmless is the one error that would make the
report worse than useless.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from ..trace import AgentAction

# --- effect classes, ordered by how much they matter -------------------

IRREVERSIBLE = "IRREVERSIBLE"
MUTATING = "MUTATING"
READ_ONLY = "READ_ONLY"
UNKNOWN = "UNKNOWN"

EFFECTS = (IRREVERSIBLE, MUTATING, UNKNOWN, READ_ONLY)


@dataclass(frozen=True)
class Rule:
    """One classification rule. `pattern` matches a capability name."""

    pattern: str
    effect: str
    note: str

    def matches(self, capability: str) -> bool:
        return re.fullmatch(self.pattern, capability, re.IGNORECASE) is not None


# Exact capability contracts are authoritative for inventory classification.
# A capability name that is not listed here may still match one of the narrow
# legacy rules below, but ambiguous compound names remain UNKNOWN.  The
# registry is deliberately explicit: a namespace identifies a domain, not an
# effect, and token position is not reliable enough to infer safety.
CAPABILITY_MANIFEST_V1: dict[str, tuple[str, str]] = {
    "crm.read_contact": (READ_ONLY, "reads a CRM contact"),
    "crm.update_contact": (MUTATING, "changes a CRM contact"),
    "email.send": (IRREVERSIBLE, "sends a message externally"),
    "payments.drain_account": (IRREVERSIBLE, "moves money"),
    "payments.get_balance": (READ_ONLY, "reads financial state"),
    "payments.transfer": (IRREVERSIBLE, "moves money"),
    "settle.view_queue": (READ_ONLY, "reads a settlement queue"),
    "storage.bulk_export": (IRREVERSIBLE, "exports data from its current scope"),
    "tool_search": (UNKNOWN, "acquires new capabilities mid-session"),
    "web_search": (READ_ONLY, "retrieves remote content"),
    "wire.get_status": (READ_ONLY, "reads payment status"),
}


# Fallback rules cover only unambiguous, established spellings.  They never
# split compound names such as read_export or fetch_and_delete: without an
# exact manifest entry those names are UNKNOWN, never assumed safe.
DEFAULT_RULES: tuple[Rule, ...] = (
    # coding agents
    Rule(r"read|view|glob|grep|ls|cat|search", READ_ONLY, "reads only"),
    Rule(r"webfetch|websearch|fetch", READ_ONLY, "retrieves remote content"),
    Rule(r"todowrite|notebookread", READ_ONLY, "local scratch state"),
    Rule(r"write|edit|multiedit|notebookedit|create_file|str_replace",
         MUTATING, "writes to the filesystem"),
    Rule(r"bash|shell|sh|exec|run_command|terminal",
         UNKNOWN, "shell: effect depends on the command"),
    Rule(r"task|agent|dispatch.*", UNKNOWN, "delegates to another agent"),
    # Money-moving fallbacks require both a financial namespace and an
    # explicit money-moving operation.  payments.get_balance is not a write.
    Rule(r"(?:payment|payout|transfer|wire|settle|disburse)s?\."
         r"(?:execute|initiate|send|transfer|wire|remit|drain)(?:[_-].*)?",
         IRREVERSIBLE, "moves money"),
    Rule(r"refund\.(issue|execute)|.*\.refund", IRREVERSIBLE, "issues a refund"),
    Rule(r".*\.(delete|destroy|purge|drop|revoke)", IRREVERSIBLE,
         "destroys data or access"),
    Rule(r".*\.(publish|deploy|release)", IRREVERSIBLE, "publishes externally"),
    Rule(r".*\.(export|download|dump)", IRREVERSIBLE, "removes data from scope"),
    Rule(r".*\.(recommend|analyse|analyze|read|get|list|search)", READ_ONLY,
         "produces a recommendation or read"),
    Rule(r".*\.(update|patch|set|create|write)", MUTATING, "changes stored state"),
)

# Shell command patterns, checked when a shell-like capability appears.
COMMAND_RULES: tuple[tuple[str, str, str], ...] = (
    (r"\bgit\s+push\b.*(--force|-f)\b", IRREVERSIBLE, "force-push rewrites history"),
    (r"\bgit\s+reset\s+--hard\b", IRREVERSIBLE, "discards work irrecoverably"),
    (r"\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)\b", IRREVERSIBLE, "recursive force delete"),
    (r"\b(npm|yarn|pnpm)\s+publish\b", IRREVERSIBLE, "publishes a package"),
    (r"\bpip\s+.*\bupload\b|\btwine\s+upload\b", IRREVERSIBLE, "publishes a package"),
    (r"\bdocker\s+push\b", IRREVERSIBLE, "publishes an image"),
    (r"\b(kubectl|helm)\s+(apply|delete|upgrade)\b", IRREVERSIBLE, "changes a live cluster"),
    (r"\bterraform\s+(apply|destroy)\b", IRREVERSIBLE, "changes live infrastructure"),
    (r"\bgh\s+(release|pr\s+merge)\b", IRREVERSIBLE, "publishes or merges"),
    (r"\bcurl\b.*(-X\s*(POST|PUT|DELETE|PATCH)|--data)", IRREVERSIBLE,
     "sends a state-changing request"),
    (r"\bgit\s+(commit|add|checkout|merge|rebase)\b", MUTATING, "changes the repository"),
    (r"\b(mv|cp|mkdir|touch|chmod|chown)\b", MUTATING, "changes the filesystem"),
    (r"\b(npm|yarn|pnpm|pip|apt|brew)\s+(install|add)\b", MUTATING,
     "installs dependencies"),
    (r"\b(ls|cat|grep|find|head|tail|wc|git\s+(status|log|diff|show))\b",
     READ_ONLY, "reads only"),
)

_SHELL_ARG_KEYS = ("command", "cmd", "script", "shell_command", "input")


@dataclass(frozen=True)
class Classification:
    effect: str
    basis: str          # "manifest" | "capability" | "command" | "default"
    note: str


def _command_text(action: AgentAction) -> str | None:
    for key in _SHELL_ARG_KEYS:
        value = action.arguments.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _rank(effect: str) -> int:
    return EFFECTS.index(effect)


def classify(
    action: AgentAction,
    rules: tuple[Rule, ...] = DEFAULT_RULES,
    manifest: dict[str, tuple[str, str]] = CAPABILITY_MANIFEST_V1,
) -> Classification:
    """Classify from an exact contract, then narrow fallback rules.

    Command inspection remains authoritative for shell-like tools because
    `Bash` alone says nothing.  Unregistered compound names do not get token
    guessed into a safe class.
    """
    contract = manifest.get(action.capability.casefold())
    if contract is not None:
        effect, note = contract
        return Classification(effect, "manifest", note)

    best: Classification | None = None
    for rule in rules:
        if not rule.matches(action.capability):
            continue
        cand = Classification(rule.effect, "capability", rule.note)
        if best is None or _rank(cand.effect) < _rank(best.effect):
            best = cand

    # A shell tool's name says nothing; the command says everything. When
    # a command rule matches it is authoritative and overrides the
    # capability-level guess in either direction -- `git status` under
    # Bash is read-only however alarming the tool name looks.
    command = _command_text(action)
    if command:
        for pattern, effect, note in COMMAND_RULES:
            if re.search(pattern, command, re.IGNORECASE):
                return Classification(effect, "command", note)

    if best is None:
        return Classification(UNKNOWN, "default", "capability not recognised")
    return best


# --- aggregation -------------------------------------------------------


@dataclass
class ToolUsage:
    """One capability, and the spread of effects it was used for.

    A shell tool is not one thing. `git status` and `git push --force`
    arrive under the same capability name, so a single label would
    overstate the finding. The per-effect counts are the honest answer;
    `worst` exists only for sorting.
    """

    capability: str
    count: int = 0
    agents: set[str] = field(default_factory=set)
    effects: dict[str, int] = field(default_factory=lambda: dict.fromkeys(EFFECTS, 0))
    notes: dict[str, str] = field(default_factory=dict)
    basis: str = "default"
    examples: list[str] = field(default_factory=list)

    def observe(self, action: AgentAction, cls: Classification) -> None:
        self.count += 1
        self.agents.add(action.agent_id)
        self.effects[cls.effect] += 1
        self.notes.setdefault(cls.effect, cls.note)
        if cls.basis == "command":
            self.basis = "command"
        elif cls.basis == "manifest" and self.basis != "command":
            self.basis = "manifest"
        elif self.basis == "default" and cls.basis == "capability":
            self.basis = "capability"
        if cls.effect == IRREVERSIBLE and len(self.examples) < 3:
            sample = _command_text(action) or _short_args(action)
            if sample and sample not in self.examples:
                self.examples.append(sample)

    @property
    def worst(self) -> str:
        """Strongest effect actually observed, not a guess about the tool."""
        for effect in EFFECTS:
            if self.effects.get(effect):
                return effect
        return UNKNOWN

    @property
    def irreversible(self) -> int:
        return self.effects.get(IRREVERSIBLE, 0)

    @property
    def note(self) -> str:
        return self.notes.get(self.worst, "")

    def spread(self) -> str:
        """e.g. '3 irreversible, 1 mutating, 1 read-only'"""
        parts = [
            f"{n} {e.lower().replace('_', '-')}"
            for e in EFFECTS
            if (n := self.effects.get(e, 0))
        ]
        return ", ".join(parts)


def _short_args(action: AgentAction, limit: int = 90) -> str:
    if not action.arguments:
        return ""
    text = ", ".join(f"{k}={v!r}" for k, v in list(action.arguments.items())[:3])
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


@dataclass
class AgentProfile:
    agent_id: str
    actions: int = 0
    capabilities: set[str] = field(default_factory=set)
    irreversible: int = 0
    mutating: int = 0
    unknown: int = 0
    read_only: int = 0
    first_seen: float | None = None
    last_seen: float | None = None

    @property
    def reach(self) -> int:
        """Distinct capabilities this agent demonstrably reached."""
        return len(self.capabilities)


@dataclass
class InventoryReport:
    source_path: str = ""
    source_format: str = ""
    lines_read: int = 0
    actions: int = 0
    coverage: float = 0.0
    skip_reasons: dict[str, int] = field(default_factory=dict)
    tools: dict[str, ToolUsage] = field(default_factory=dict)
    agents: dict[str, AgentProfile] = field(default_factory=dict)
    time_span: tuple[float, float] | None = None

    def by_effect(self) -> dict[str, int]:
        counts = dict.fromkeys(EFFECTS, 0)
        for usage in self.tools.values():
            for effect, n in usage.effects.items():
                counts[effect] += n
        return counts

    def irreversible_tools(self) -> list[ToolUsage]:
        return sorted(
            (t for t in self.tools.values() if t.irreversible),
            key=lambda t: -t.irreversible,
        )

    def widest_reach(self) -> list[AgentProfile]:
        return sorted(self.agents.values(), key=lambda a: (-a.reach, -a.irreversible))


def build_inventory(result: Any, rules: tuple[Rule, ...] = DEFAULT_RULES) -> InventoryReport:
    """result: an IngestResult from agent_dna.scan.ingest."""
    report = InventoryReport(
        source_path=result.source_path,
        source_format=result.source_format,
        lines_read=result.lines_read,
        actions=result.understood,
        coverage=result.coverage,
        skip_reasons=result.skip_reasons(),
        time_span=result.time_span(),
    )

    per_agent: dict[str, AgentProfile] = defaultdict(lambda: AgentProfile(""))

    for action in result.actions:
        cls = classify(action, rules)

        usage = report.tools.get(action.capability)
        if usage is None:
            usage = ToolUsage(capability=action.capability)
            report.tools[action.capability] = usage
        usage.observe(action, cls)

        profile = per_agent[action.agent_id]
        if not profile.agent_id:
            profile.agent_id = action.agent_id
        profile.actions += 1
        profile.capabilities.add(action.capability)
        if cls.effect == IRREVERSIBLE:
            profile.irreversible += 1
        elif cls.effect == MUTATING:
            profile.mutating += 1
        elif cls.effect == UNKNOWN:
            profile.unknown += 1
        else:
            profile.read_only += 1
        ts = action.timestamp
        profile.first_seen = ts if profile.first_seen is None else min(profile.first_seen, ts)
        profile.last_seen = ts if profile.last_seen is None else max(profile.last_seen, ts)

    report.agents = dict(per_agent)
    return report
