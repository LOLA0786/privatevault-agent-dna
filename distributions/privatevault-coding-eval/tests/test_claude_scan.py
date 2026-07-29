from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path
from typing import Any

import pytest

from privatevault_coding_eval.cli import main
from privatevault_coding_eval.scan import (
    EvidenceState,
    ScanFormatError,
    iter_claude_code_events,
    write_events_jsonl,
)


def _record(
    *,
    session_id: str = "private-session-123",
    tool_id: str = "private-tool-456",
    tool_name: str = "Write",
    tool_input: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if tool_input is None:
        tool_input = {
            "file_path": "/customer/secret.py",
            "content": "API_TOKEN=super-secret",
        }

    return {
        "type": "assistant",
        "sessionId": session_id,
        "timestamp": "2026-07-29T01:02:03Z",
        "message": {
            "content": [
                {
                    "type": "tool_use",
                    "id": tool_id,
                    "name": tool_name,
                    "input": tool_input,
                }
            ]
        },
    }


def _write_records(
    path: Path,
    *records: dict[str, Any],
) -> bytes:
    encoded = "".join(
        json.dumps(record) + "\n"
        for record in records
    ).encode("utf-8")
    path.write_bytes(encoded)
    return encoded


def test_scan_minimizes_private_data(
    tmp_path: Path,
) -> None:
    source = tmp_path / "customer-private.jsonl"
    source_bytes = _write_records(
        source,
        _record(),
    )

    events = list(
        iter_claude_code_events(source)
    )

    assert len(events) == 1
    event = events[0]
    assert event.sequence == 0
    assert event.tool_name == "Write"
    assert event.evidence_state is EvidenceState.OBSERVED
    assert event.provenance.source_line == 1
    assert event.provenance.source_file_digest == (
        "sha256:"
        + hashlib.sha256(source_bytes).hexdigest()
    )

    encoded = json.dumps(
        event.to_dict(),
        sort_keys=True,
    )

    for private_value in (
        "private-session-123",
        "private-tool-456",
        "/customer/secret.py",
        "API_TOKEN",
        "super-secret",
        str(source),
    ):
        assert private_value not in encoded


def test_bash_segments_become_ordered_events(
    tmp_path: Path,
) -> None:
    source = tmp_path / "bash.jsonl"
    command = "git status && git push origin main"
    _write_records(
        source,
        _record(
            tool_name="Bash",
            tool_input={"command": command},
        ),
    )

    events = list(
        iter_claude_code_events(source)
    )

    assert len(events) == 2
    assert [event.sequence for event in events] == [0, 1]
    assert len(
        {event.event_id for event in events}
    ) == 2
    assert events[0].input_digest == events[1].input_digest
    assert events[1].sink_id == "sink:git-push"
    assert command not in json.dumps(
        [event.to_dict() for event in events]
    )


def test_malformed_source_preserves_output(
    tmp_path: Path,
) -> None:
    source = tmp_path / "broken.jsonl"
    source.write_text(
        json.dumps(_record()) + "\n{not-json}\n",
        encoding="utf-8",
    )
    output = tmp_path / "events.jsonl"
    sentinel = "do-not-replace\n"
    output.write_text(sentinel, encoding="utf-8")

    with pytest.raises(
        ScanFormatError,
        match="invalid JSON",
    ):
        write_events_jsonl(
            output,
            iter_claude_code_events(source),
        )

    assert output.read_text(
        encoding="utf-8",
    ) == sentinel
    assert not list(
        tmp_path.glob(".events.jsonl.*")
    )


def test_cli_writes_owner_only_jsonl(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "session.jsonl"
    output = tmp_path / "events.jsonl"
    _write_records(
        source,
        _record(
            tool_name="Read",
            tool_input={
                "file_path": "/private/source.py",
            },
        ),
    )

    result = main(
        [
            "scan",
            "--claude-jsonl",
            str(source),
            "--output",
            str(output),
        ]
    )

    assert result == 0
    assert "Events observed    1" in (
        capsys.readouterr().out
    )
    assert stat.S_IMODE(
        output.stat().st_mode
    ) == 0o600

    documents = [
        json.loads(line)
        for line in output.read_text(
            encoding="utf-8",
        ).splitlines()
    ]
    assert len(documents) == 1
    assert documents[0]["spec"] == (
        "pv-coding-observed-event/0.1"
    )
