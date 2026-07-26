"""Normalize heterogeneous agent logs into AgentAction.

Four shapes are recognized, because between them they cover most of
what an enterprise actually has sitting on disk today:

    mcp       MCP JSON-RPC frames (tools/call), one per line
    openai    OpenAI chat-completion records with tool_calls
    anthropic Anthropic message records with tool_use blocks
    generic   flat JSONL: one object per action
    csv       flat CSV with a header row

Rules this module holds to, because the scan's output is a claim about
somebody else's production traffic:

  * Never invent a field. No default agent_id, no synthesized
    timestamp, no guessed capability. A row missing any of the three is
    skipped with a reason and counted.
  * Never silently drop. Every skipped row is retained with its line
    number and a short reason so the operator can see exactly how much
    of their log was not understood, and why.
  * Never reorder. Actions are emitted in file order; the caller sorts
    if it wants to, and rate/window analysis depends on knowing whether
    the source was ordered in the first place.
  * A malformed line is a skipped row, not a crash. Scanning 40,000
    lines must not die on line 3.
"""

from __future__ import annotations

import csv as _csv
import io
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..trace import AgentAction

FORMATS = ("auto", "mcp", "openai", "anthropic", "generic", "csv")

# Keys we accept for each required field, in priority order. Real logs
# disagree about names; this is the whole of the flexibility on offer.
_AGENT_KEYS = (
    "agent_id", "agentId", "agent", "actor_id", "actor",
    "session_id", "sessionId", "run_id", "runId",
)
_CAPABILITY_KEYS = (
    "capability", "tool", "tool_name", "toolName", "name",
    "function", "function_name", "action", "verb", "method",
)
_TIMESTAMP_KEYS = (
    "timestamp", "ts", "time", "created_at", "createdAt",
    "start_time", "startTime", "@timestamp",
)
_ARGUMENT_KEYS = (
    "arguments", "args", "input", "inputs", "parameters", "params",
)
_REQUEST_KEYS = ("request_id", "requestId", "id", "call_id", "callId")

_MAX_RAW_ECHO = 160


@dataclass(frozen=True)
class SkippedRow:
    """A line that could not become an action, and why."""

    line_no: int
    reason: str
    raw: str

    def to_dict(self) -> dict[str, Any]:
        return {"line_no": self.line_no, "reason": self.reason, "raw": self.raw}


@dataclass
class IngestResult:
    actions: list[AgentAction] = field(default_factory=list)
    skipped: list[SkippedRow] = field(default_factory=list)
    source_format: str = "unknown"
    source_path: str = ""
    lines_read: int = 0

    @property
    def understood(self) -> int:
        return len(self.actions)

    @property
    def coverage(self) -> float:
        """Fraction of non-blank lines that became actions. Reported
        verbatim: a scan over a log we only half understood is worth
        exactly half as much, and the operator should be told so."""
        total = len(self.actions) + len(self.skipped)
        return (len(self.actions) / total) if total else 0.0

    def skip_reasons(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for row in self.skipped:
            counts[row.reason] = counts.get(row.reason, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

    def agents(self) -> list[str]:
        return sorted({a.agent_id for a in self.actions})

    def time_span(self) -> tuple[float, float] | None:
        if not self.actions:
            return None
        stamps = [a.timestamp for a in self.actions]
        return (min(stamps), max(stamps))


# ---------------------------------------------------------------------
# field coercion
# ---------------------------------------------------------------------


def _first(obj: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for k in keys:
        if k in obj and obj[k] not in (None, ""):
            return obj[k]
    return None


def parse_timestamp(value: Any) -> float | None:
    """Epoch seconds, epoch millis, or ISO 8601. Returns None rather
    than a fallback -- an action with an invented time would silently
    corrupt every rate and window calculation downstream."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        ts = float(value)
        # Heuristic only for the magnitude, never for existence:
        # anything past year ~2286 in seconds is milliseconds.
        if ts > 1e11:
            ts /= 1000.0
        return ts if ts > 0 else None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            return parse_timestamp(float(text))
        except ValueError:
            pass
        cleaned = text.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(cleaned)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.timestamp()
    return None


def _coerce_arguments(value: Any) -> dict[str, Any]:
    """Tool arguments arrive as a dict or as a JSON string. A string
    that will not parse is kept under a reserved key rather than
    discarded -- it may be the only record of what was attempted."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            return {"_raw": value}
        return parsed if isinstance(parsed, dict) else {"_value": parsed}
    if value is None:
        return {}
    return {"_value": value}


def _normalize_capability(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    cap = value.strip()
    return cap or None


def _build_action(
    obj: dict[str, Any],
    line_no: int,
    source_format: str,
) -> AgentAction | SkippedRow:
    raw = json.dumps(obj, default=str)[:_MAX_RAW_ECHO]

    agent_id = _first(obj, _AGENT_KEYS)
    if not isinstance(agent_id, str) or not agent_id.strip():
        return SkippedRow(line_no, "no agent identifier", raw)

    capability = _normalize_capability(_first(obj, _CAPABILITY_KEYS))
    if capability is None:
        return SkippedRow(line_no, "no capability/tool name", raw)

    timestamp = parse_timestamp(_first(obj, _TIMESTAMP_KEYS))
    if timestamp is None:
        return SkippedRow(line_no, "no parseable timestamp", raw)

    request_id = _first(obj, _REQUEST_KEYS)
    outcome = obj.get("outcome") or obj.get("status") or "ok"
    if outcome not in ("ok", "error", "blocked"):
        outcome = "error" if str(outcome).lower() in ("fail", "failed") else "ok"

    return AgentAction(
        agent_id=agent_id.strip(),
        capability=capability,
        timestamp=timestamp,
        arguments=_coerce_arguments(_first(obj, _ARGUMENT_KEYS)),
        context={"source_format": source_format, "source_line": line_no},
        request_id=str(request_id) if request_id is not None else None,
        outcome=outcome,
    )


# ---------------------------------------------------------------------
# per-format extraction: log line -> zero or more flat dicts
# ---------------------------------------------------------------------


def _extract_mcp(obj: dict[str, Any]) -> list[dict[str, Any]]:
    """MCP JSON-RPC frame. Only tools/call carries an action; every
    other method (initialize, tools/list, notifications) is protocol
    chatter and is not an agent action."""
    if obj.get("method") != "tools/call":
        return []
    params = obj.get("params") or {}
    flat = dict(obj)
    flat.pop("params", None)
    flat["tool"] = params.get("name")
    flat["arguments"] = params.get("arguments")
    meta = params.get("_meta") or {}
    for key in _AGENT_KEYS:
        if key in meta:
            flat[key] = meta[key]
    return [flat]


def _extract_openai(obj: dict[str, Any]) -> list[dict[str, Any]]:
    """One chat-completion record may carry several tool_calls; each is
    a separate agent action."""
    calls: list[dict[str, Any]] = []
    choices = obj.get("choices") or []
    messages = [c.get("message", {}) for c in choices if isinstance(c, dict)]
    if "message" in obj and isinstance(obj["message"], dict):
        messages.append(obj["message"])
    if "tool_calls" in obj:
        messages.append(obj)

    for msg in messages:
        for call in msg.get("tool_calls") or []:
            fn = call.get("function") or {}
            flat = {k: v for k, v in obj.items() if k != "choices"}
            flat["tool"] = fn.get("name")
            flat["arguments"] = fn.get("arguments")
            flat["call_id"] = call.get("id")
            calls.append(flat)
    return calls


def _extract_anthropic(obj: dict[str, Any]) -> list[dict[str, Any]]:
    """Anthropic messages carry tool_use blocks in content."""
    calls: list[dict[str, Any]] = []
    content = obj.get("content")
    if isinstance(content, list):
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "tool_use":
                continue
            flat = {k: v for k, v in obj.items() if k != "content"}
            flat["tool"] = block.get("name")
            flat["arguments"] = block.get("input")
            flat["call_id"] = block.get("id")
            calls.append(flat)
    return calls


def _extract_generic(obj: dict[str, Any]) -> list[dict[str, Any]]:
    return [obj]


_EXTRACTORS = {
    "mcp": _extract_mcp,
    "openai": _extract_openai,
    "anthropic": _extract_anthropic,
    "generic": _extract_generic,
}


# ---------------------------------------------------------------------
# detection
# ---------------------------------------------------------------------


def _sample_lines(path: Path, limit: int = 50) -> list[str]:
    out: list[str] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(line)
            if len(out) >= limit:
                break
    return out


def detect_format(path: str | Path) -> str:
    """Best-effort sniff. Returns a concrete format name, never 'auto'.

    Detection is a convenience, not a guarantee: it looks at up to 50
    lines and picks the shape that explains the most of them. Pass an
    explicit format when the answer matters.
    """
    path = Path(path)
    if path.suffix.lower() in (".csv", ".tsv"):
        return "csv"

    sample = _sample_lines(path)
    if not sample:
        return "generic"

    parsed: list[dict[str, Any]] = []
    for line in sample:
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            parsed.append(obj)

    if not parsed:
        # Not JSONL. If the first line looks like a header, treat as CSV.
        if "," in sample[0]:
            return "csv"
        return "generic"

    scores = {
        "mcp": sum(1 for o in parsed if o.get("method") or "jsonrpc" in o),
        "openai": sum(1 for o in parsed if "choices" in o or "tool_calls" in o),
        "anthropic": sum(
            1
            for o in parsed
            if isinstance(o.get("content"), list)
            and any(
                isinstance(b, dict) and b.get("type") == "tool_use"
                for b in o["content"]
            )
        ),
    }
    best, score = max(scores.items(), key=lambda kv: kv[1])
    return best if score else "generic"


# ---------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------


def _iter_json_lines(path: Path) -> Iterator[tuple[int, str]]:
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        yield from enumerate(fh, start=1)


def _ingest_csv(path: Path, result: IngestResult) -> None:
    with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        text = fh.read()
    if not text.strip():
        return
    try:
        dialect = _csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
    except _csv.Error:
        dialect = _csv.excel
    reader = _csv.DictReader(io.StringIO(text), dialect=dialect)
    for line_no, row in enumerate(reader, start=2):  # 1 is the header
        result.lines_read += 1
        clean = {k.strip(): v for k, v in row.items() if k}
        built = _build_action(clean, line_no, "csv")
        if isinstance(built, SkippedRow):
            result.skipped.append(built)
        else:
            result.actions.append(built)


def _ingest_row(
    flat: dict[str, Any],
    line_no: int,
    resolved: str,
    agent_id: str | None,
    result: IngestResult,
) -> None:
    built = _build_action(flat, line_no, resolved)
    if isinstance(built, SkippedRow) and built.reason == "no agent identifier" \
            and agent_id:
        retry = dict(flat)
        retry["agent_id"] = agent_id
        built = _build_action(retry, line_no, resolved)
        if isinstance(built, AgentAction):
            built.context["agent_id_supplied"] = True
    if isinstance(built, SkippedRow):
        result.skipped.append(built)
    else:
        result.actions.append(built)


def _ingest_jsonl(
    path: Path,
    resolved: str,
    agent_id: str | None,
    result: IngestResult,
) -> None:
    extract = _EXTRACTORS[resolved]
    for line_no, line in _iter_json_lines(path):
        stripped = line.strip()
        if not stripped:
            continue
        result.lines_read += 1
        try:
            obj = json.loads(stripped)
        except ValueError as exc:
            result.skipped.append(
                SkippedRow(line_no, f"invalid JSON: {exc.args[0][:60]}",
                           stripped[:_MAX_RAW_ECHO])
            )
            continue
        if not isinstance(obj, dict):
            result.skipped.append(
                SkippedRow(line_no, "line is not a JSON object",
                           stripped[:_MAX_RAW_ECHO])
            )
            continue
        # Protocol chatter in a well-formed log is expected and is not a
        # failure to understand it, so an empty extraction is not a skip.
        for flat in extract(obj):
            _ingest_row(flat, line_no, resolved, agent_id, result)


def ingest(
    path: str | Path,
    fmt: str = "auto",
    *,
    agent_id: str | None = None,
) -> IngestResult:
    """Read a log file into actions.

    agent_id is a LAST-RESORT override for logs that genuinely carry no
    identity (a single-agent stdio session, say). It is applied only to
    rows that would otherwise be skipped for that reason, and the
    substitution is recorded in the action's context so the report can
    say the identity was supplied rather than observed.
    """
    if fmt not in FORMATS:
        raise ValueError(f"unknown format {fmt!r}; expected one of {FORMATS}")

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"no such log file: {path}")

    resolved = detect_format(path) if fmt == "auto" else fmt
    result = IngestResult(source_format=resolved, source_path=str(path))

    if resolved == "csv":
        _ingest_csv(path, result)
    else:
        _ingest_jsonl(path, resolved, agent_id, result)
    return result
