"""Strict privacy-minimizing Claude Code JSONL adapter."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any

from .classifier import classify_tool, digest_json, pseudonymous_id
from .model import (
    EVENT_SPEC,
    CodingEvent,
    EventProvenance,
    EvidenceState,
    ScanFormatError,
)

ADAPTER_VERSION = "claude-code-jsonl/0.1"
SOURCE_SYSTEM = "claude-code-jsonl"
_MAX_LINE_CHARS = 8 * 1024 * 1024


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _object(value: Any, location: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ScanFormatError(f"{location}: expected object")
    return value


def _text(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ScanFormatError(
            f"{location}: expected non-empty string"
        )
    return value


def _load_record(line: str, line_number: int) -> Mapping[str, Any]:
    if len(line) > _MAX_LINE_CHARS:
        raise ScanFormatError(
            f"line {line_number}: record too large"
        )
    try:
        value = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ScanFormatError(
            f"line {line_number}: invalid JSON"
        ) from exc
    return _object(value, f"line {line_number}")


def _tool_uses(
    record: Mapping[str, Any],
    line_number: int,
) -> Iterator[Mapping[str, Any]]:
    if record.get("type") != "assistant":
        return
    message = _object(
        record.get("message"),
        f"line {line_number}.message",
    )
    content = message.get("content")
    if not isinstance(content, list):
        raise ScanFormatError(
            f"line {line_number}.message.content: expected array"
        )
    for index, raw_item in enumerate(content):
        item = _object(
            raw_item,
            f"line {line_number}.message.content[{index}]",
        )
        if item.get("type") == "tool_use":
            yield item


def _timestamp(
    record: Mapping[str, Any],
    line_number: int,
) -> str | None:
    value = record.get("timestamp")
    if value is None:
        return None
    if not isinstance(value, str):
        raise ScanFormatError(
            f"line {line_number}.timestamp: expected string or null"
        )
    if value.endswith("+00:00"):
        return value[:-6] + "Z"
    return value


def _tool_events(
    tool: Mapping[str, Any],
    *,
    raw_session_id: str,
    timestamp: str | None,
    sequence: int,
    source_path_digest: str,
    source_file_digest: str,
    source_line: int,
    tool_ordinal: int,
) -> tuple[CodingEvent, ...]:
    location = f"line {source_line}.tool[{tool_ordinal}]"
    tool_use_id = _text(tool.get("id"), f"{location}.id")
    tool_name = _text(tool.get("name"), f"{location}.name")
    tool_input = _object(tool.get("input"), f"{location}.input")
    provenance = EventProvenance(
        source_system=SOURCE_SYSTEM,
        source_path_digest=source_path_digest,
        source_file_digest=source_file_digest,
        source_line=source_line,
        adapter_version=ADAPTER_VERSION,
    )
    events: list[CodingEvent] = []
    for offset, classification in enumerate(
        classify_tool(tool_name, tool_input)
    ):
        event_seed = "\x1f".join(
            (
                raw_session_id,
                tool_use_id,
                str(offset),
                classification.rule_id,
            )
        )
        events.append(
            CodingEvent.from_dict(
                {
                    "spec": EVENT_SPEC,
                    "event_id": pseudonymous_id(
                        "event", event_seed
                    ),
                    "session_id": pseudonymous_id(
                        "session", raw_session_id
                    ),
                    "agent_id": pseudonymous_id(
                        "agent", raw_session_id
                    ),
                    "sequence": sequence + offset,
                    "timestamp": timestamp,
                    "tool_name": tool_name,
                    "capability": classification.capability,
                    "sink_id": classification.sink_id,
                    "evidence_state": EvidenceState.OBSERVED.value,
                    "input_digest": digest_json(tool_input),
                    "provenance": provenance.to_dict(),
                },
                path=location,
            )
        )
    return tuple(events)


def iter_claude_code_events(path: Path) -> Iterator[CodingEvent]:
    """Yield observed events from one Claude Code transcript."""

    resolved = path.resolve(strict=True)
    path_digest = _digest_bytes(str(resolved).encode("utf-8"))
    file_digest = _file_digest(resolved)
    raw_session_id: str | None = None
    seen_tool_ids: set[str] = set()
    sequence = 0

    try:
        with resolved.open("r", encoding="utf-8") as source:
            for line_number, line in enumerate(source, start=1):
                if not line.strip():
                    continue
                record = _load_record(line, line_number)
                tools = tuple(_tool_uses(record, line_number))
                if not tools:
                    continue
                current_session_id = _text(
                    record.get("sessionId"),
                    f"line {line_number}.sessionId",
                )
                if raw_session_id is None:
                    raw_session_id = current_session_id
                elif current_session_id != raw_session_id:
                    raise ScanFormatError(
                        f"line {line_number}: multiple sessions"
                    )
                for tool_ordinal, tool in enumerate(tools):
                    tool_id = _text(
                        tool.get("id"),
                        f"line {line_number}.tool[{tool_ordinal}].id",
                    )
                    if tool_id in seen_tool_ids:
                        raise ScanFormatError(
                            f"line {line_number}: duplicate tool use"
                        )
                    seen_tool_ids.add(tool_id)
                    events = _tool_events(
                        tool,
                        raw_session_id=current_session_id,
                        timestamp=_timestamp(record, line_number),
                        sequence=sequence,
                        source_path_digest=path_digest,
                        source_file_digest=file_digest,
                        source_line=line_number,
                        tool_ordinal=tool_ordinal,
                    )
                    yield from events
                    sequence += len(events)
    except UnicodeError as exc:
        raise ScanFormatError(
            "source: expected UTF-8 JSONL"
        ) from exc

    if _file_digest(resolved) != file_digest:
        raise ScanFormatError("source changed during scan")


def write_events_jsonl(
    path: Path,
    events: Iterable[CodingEvent],
) -> int:
    """Atomically write events with owner-only permissions."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    count = 0
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
        ) as output:
            descriptor = -1
            for event in events:
                output.write(
                    json.dumps(
                        event.to_dict(),
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n"
                )
                count += 1
            if count == 0:
                raise ScanFormatError(
                    "source: no observed tool calls"
                )
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    return count
