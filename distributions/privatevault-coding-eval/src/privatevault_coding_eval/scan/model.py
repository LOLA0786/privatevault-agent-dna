"""Strict privacy-minimizing event contract for coding-agent scans."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

EVENT_SPEC = "pv-coding-observed-event/0.1"

SHA256_RE = re.compile(
    r"sha256:[0-9a-f]{64}\Z"
)

RFC3339_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T"
    r"\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,6})?Z\Z"
)


class ScanFormatError(ValueError):
    """Input cannot be interpreted without guessing."""


class EvidenceState(StrEnum):
    """Evidence seen in activity or declared configuration."""

    OBSERVED = "OBSERVED"
    DECLARED = "DECLARED"


def _mapping(
    value: Any,
    path: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ScanFormatError(
            f"{path}: expected object"
        )
    return value


def _string(
    value: Any,
    path: str,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
    ):
        raise ScanFormatError(
            f"{path}: expected non-empty string"
        )
    return value


def _digest(
    value: Any,
    path: str,
) -> str:
    encoded = _string(
        value,
        path,
    )

    if not SHA256_RE.fullmatch(encoded):
        raise ScanFormatError(
            f"{path}: malformed SHA-256 digest"
        )

    return encoded


def _exact(
    value: Mapping[str, Any],
    required: set[str],
    path: str,
) -> None:
    if set(value) != required:
        missing = sorted(
            required - set(value)
        )
        unknown = sorted(
            set(value) - required
        )

        raise ScanFormatError(
            f"{path}: invalid fields "
            f"missing={missing}, unknown={unknown}"
        )


def _timestamp(
    value: Any,
    path: str,
) -> str | None:
    if value is None:
        return None

    encoded = _string(
        value,
        path,
    )

    if not RFC3339_RE.fullmatch(encoded):
        raise ScanFormatError(
            f"{path}: expected RFC 3339 UTC timestamp"
        )

    try:
        datetime.fromisoformat(
            encoded[:-1] + "+00:00"
        )
    except ValueError as exc:
        raise ScanFormatError(
            f"{path}: malformed timestamp"
        ) from exc

    return encoded


@dataclass(frozen=True)
class EventProvenance:
    source_system: str
    source_path_digest: str
    source_file_digest: str
    source_line: int
    adapter_version: str

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        path: str,
    ) -> EventProvenance:
        value = _mapping(
            raw,
            path,
        )

        _exact(
            value,
            {
                "source_system",
                "source_path_digest",
                "source_file_digest",
                "source_line",
                "adapter_version",
            },
            path,
        )

        line = value["source_line"]

        if (
            isinstance(line, bool)
            or not isinstance(line, int)
            or line < 1
        ):
            raise ScanFormatError(
                f"{path}.source_line: "
                "expected integer >= 1"
            )

        return cls(
            source_system=_string(
                value["source_system"],
                f"{path}.source_system",
            ),
            source_path_digest=_digest(
                value["source_path_digest"],
                f"{path}.source_path_digest",
            ),
            source_file_digest=_digest(
                value["source_file_digest"],
                f"{path}.source_file_digest",
            ),
            source_line=line,
            adapter_version=_string(
                value["adapter_version"],
                f"{path}.adapter_version",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_system": self.source_system,
            "source_path_digest": (
                self.source_path_digest
            ),
            "source_file_digest": (
                self.source_file_digest
            ),
            "source_line": self.source_line,
            "adapter_version": self.adapter_version,
        }


@dataclass(frozen=True)
class CodingEvent:
    event_id: str
    session_id: str
    agent_id: str
    sequence: int
    timestamp: str | None
    tool_name: str
    capability: str
    sink_id: str | None
    evidence_state: EvidenceState
    input_digest: str
    provenance: EventProvenance

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        path: str = "event",
    ) -> CodingEvent:
        value = _mapping(
            raw,
            path,
        )

        _exact(
            value,
            {
                "spec",
                "event_id",
                "session_id",
                "agent_id",
                "sequence",
                "timestamp",
                "tool_name",
                "capability",
                "sink_id",
                "evidence_state",
                "input_digest",
                "provenance",
            },
            path,
        )

        if value["spec"] != EVENT_SPEC:
            raise ScanFormatError(
                f"{path}.spec: unsupported contract"
            )

        sequence = value["sequence"]

        if (
            isinstance(sequence, bool)
            or not isinstance(sequence, int)
            or sequence < 0
        ):
            raise ScanFormatError(
                f"{path}.sequence: expected integer >= 0"
            )

        sink = value["sink_id"]

        if sink is not None:
            sink = _string(
                sink,
                f"{path}.sink_id",
            )

            if not sink.startswith("sink:"):
                raise ScanFormatError(
                    f"{path}.sink_id: expected sink: prefix"
                )

        try:
            evidence = EvidenceState(
                value["evidence_state"]
            )
        except (TypeError, ValueError) as exc:
            raise ScanFormatError(
                f"{path}.evidence_state: unsupported value"
            ) from exc

        return cls(
            event_id=_string(
                value["event_id"],
                f"{path}.event_id",
            ),
            session_id=_string(
                value["session_id"],
                f"{path}.session_id",
            ),
            agent_id=_string(
                value["agent_id"],
                f"{path}.agent_id",
            ),
            sequence=sequence,
            timestamp=_timestamp(
                value["timestamp"],
                f"{path}.timestamp",
            ),
            tool_name=_string(
                value["tool_name"],
                f"{path}.tool_name",
            ),
            capability=_string(
                value["capability"],
                f"{path}.capability",
            ),
            sink_id=sink,
            evidence_state=evidence,
            input_digest=_digest(
                value["input_digest"],
                f"{path}.input_digest",
            ),
            provenance=EventProvenance.from_dict(
                value["provenance"],
                f"{path}.provenance",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "spec": EVENT_SPEC,
            "event_id": self.event_id,
            "session_id": self.session_id,
            "agent_id": self.agent_id,
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "tool_name": self.tool_name,
            "capability": self.capability,
            "sink_id": self.sink_id,
            "evidence_state": (
                self.evidence_state.value
            ),
            "input_digest": self.input_digest,
            "provenance": self.provenance.to_dict(),
        }
