"""Ingest must be honest about what it did and did not understand.

The scan's output is a claim about a customer's production traffic. A
single invented action makes the whole number untrustworthy, so these
tests are weighted toward what ingest REFUSES to do: no default agent,
no synthesized timestamp, no guessed capability, no silent drops.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from agent_dna.scan import IngestResult, detect_format, ingest
from agent_dna.scan.ingest import parse_timestamp
from agent_dna.trace import AgentAction


def _write(tmp_path, name: str, lines) -> str:
    p = tmp_path / name
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(p)


# ---------------------------------------------------------------- mcp


MCP_LINES = [
    json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
    json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    json.dumps({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "timestamp": "2026-06-01T10:00:00Z",
        "params": {
            "name": "payments.wire_transfer",
            "arguments": {"amount": 340000, "to": "ACME-99"},
            "_meta": {"agent_id": "treasury-agent-07"},
        },
    }),
    json.dumps({
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "timestamp": "2026-06-01T10:00:05Z",
        "params": {
            "name": "crm.read_contact",
            "arguments": {"id": "C-1"},
            "_meta": {"agent_id": "sales-agent-01"},
        },
    }),
]


def test_mcp_frames_become_actions(tmp_path) -> None:
    path = _write(tmp_path, "mcp.jsonl", MCP_LINES)
    result = ingest(path)

    assert result.source_format == "mcp"
    assert len(result.actions) == 2
    wire = result.actions[0]
    assert wire.agent_id == "treasury-agent-07"
    assert wire.capability == "payments.wire_transfer"
    assert wire.arguments["amount"] == 340000
    assert result.agents() == ["sales-agent-01", "treasury-agent-07"]


def test_mcp_protocol_chatter_is_not_counted_as_a_failure(tmp_path) -> None:
    """initialize and tools/list are not agent actions. Skipping them
    must not show up as 'we did not understand your log'."""
    path = _write(tmp_path, "mcp.jsonl", MCP_LINES)
    result = ingest(path)

    assert result.skipped == []
    assert result.coverage == 1.0


# ------------------------------------------------------------- openai


def test_openai_record_with_several_tool_calls_yields_several_actions(
    tmp_path,
) -> None:
    line = json.dumps({
        "agent_id": "ops-agent",
        "created_at": 1780000000,
        "choices": [{"message": {"tool_calls": [
            {"id": "c1", "function": {"name": "search",
                                      "arguments": '{"q": "x"}'}},
            {"id": "c2", "function": {"name": "send_email",
                                      "arguments": '{"to": "a@b.c"}'}},
        ]}}],
    })
    path = _write(tmp_path, "openai.jsonl", [line])
    result = ingest(path)

    assert result.source_format == "openai"
    assert [a.capability for a in result.actions] == ["search", "send_email"]
    assert result.actions[0].arguments == {"q": "x"}
    assert result.actions[0].request_id == "c1"


# ---------------------------------------------------------- anthropic


def test_anthropic_tool_use_blocks_become_actions(tmp_path) -> None:
    line = json.dumps({
        "agent_id": "research-agent",
        "timestamp": "2026-06-02T08:30:00+05:30",
        "content": [
            {"type": "text", "text": "let me look that up"},
            {"type": "tool_use", "id": "tu_1", "name": "web_search",
             "input": {"query": "rbi dual control"}},
        ],
    })
    path = _write(tmp_path, "anthropic.jsonl", [line])
    result = ingest(path)

    assert result.source_format == "anthropic"
    assert len(result.actions) == 1
    assert result.actions[0].capability == "web_search"
    assert result.actions[0].arguments == {"query": "rbi dual control"}


def test_timezone_aware_timestamps_are_not_treated_as_utc(tmp_path) -> None:
    """+05:30 is Mumbai. Reading it as UTC would shift every action by
    five and a half hours and silently corrupt window analysis."""
    aware = parse_timestamp("2026-06-02T08:30:00+05:30")
    utc = parse_timestamp("2026-06-02T08:30:00Z")
    assert aware is not None and utc is not None
    assert utc - aware == pytest.approx(5.5 * 3600)


# ------------------------------------------------------------ generic


def test_generic_jsonl_and_csv_agree_on_the_same_data(tmp_path) -> None:
    rows = [
        {"agent_id": "a1", "capability": "pay", "timestamp": 1780000000,
         "arguments": {"amount": 10}},
        {"agent_id": "a1", "capability": "read", "timestamp": 1780000060,
         "arguments": {}},
    ]
    jsonl = _write(tmp_path, "g.jsonl", [json.dumps(r) for r in rows])
    csv_path = tmp_path / "g.csv"
    csv_path.write_text(
        "agent_id,capability,timestamp,arguments\n"
        'a1,pay,1780000000,"{""amount"": 10}"\n'
        "a1,read,1780000060,{}\n",
        encoding="utf-8",
    )

    from_json = ingest(jsonl)
    from_csv = ingest(str(csv_path))

    assert from_csv.source_format == "csv"
    assert [a.capability for a in from_json.actions] == \
           [a.capability for a in from_csv.actions]
    assert [a.timestamp for a in from_json.actions] == \
           [a.timestamp for a in from_csv.actions]
    assert from_csv.actions[0].arguments == {"amount": 10}


# --------------------------------------------------- refusal to guess


@pytest.mark.parametrize(
    ("row", "reason"),
    [
        ({"capability": "pay", "timestamp": 1780000000},
         "no agent identifier"),
        ({"agent_id": "a1", "timestamp": 1780000000},
         "no capability/tool name"),
        ({"agent_id": "a1", "capability": "pay"},
         "no parseable timestamp"),
        ({"agent_id": "a1", "capability": "pay", "timestamp": "not a date"},
         "no parseable timestamp"),
    ],
)
def test_incomplete_rows_are_skipped_not_invented(
    tmp_path, row: dict, reason: str
) -> None:
    path = _write(tmp_path, "g.jsonl", [json.dumps(row)])
    result = ingest(path)

    assert result.actions == []
    assert len(result.skipped) == 1
    assert result.skipped[0].reason == reason
    assert result.skipped[0].line_no == 1


def test_malformed_line_does_not_abort_the_scan(tmp_path) -> None:
    """A 40,000-line log must not die on line 2."""
    good = json.dumps(
        {"agent_id": "a1", "capability": "pay", "timestamp": 1780000000}
    )
    path = _write(tmp_path, "g.jsonl", [good, "{not json", good])
    result = ingest(path)

    assert len(result.actions) == 2
    assert len(result.skipped) == 1
    assert result.skipped[0].reason.startswith("invalid JSON")


def test_coverage_is_reported_verbatim(tmp_path) -> None:
    """Half-understood logs produce half-strength claims, and the
    operator has to be able to see that."""
    good = json.dumps(
        {"agent_id": "a1", "capability": "pay", "timestamp": 1780000000}
    )
    bad = json.dumps({"capability": "pay", "timestamp": 1780000000})
    path = _write(tmp_path, "g.jsonl", [good, bad, good, bad])
    result = ingest(path)

    assert result.coverage == 0.5
    assert result.skip_reasons() == {"no agent identifier": 2}


def test_supplied_agent_id_is_marked_as_supplied(tmp_path) -> None:
    """A single-agent stdio session legitimately has no identity in the
    log. Accepting an override is fine; hiding that it was an override
    is not."""
    row = json.dumps({"capability": "pay", "timestamp": 1780000000})
    path = _write(tmp_path, "g.jsonl", [row])

    without = ingest(path)
    assert without.actions == []

    with_id = ingest(path, agent_id="stdio-session-1")
    assert len(with_id.actions) == 1
    assert with_id.actions[0].agent_id == "stdio-session-1"
    assert with_id.actions[0].context["agent_id_supplied"] is True


def test_supplied_agent_id_never_masks_a_different_defect(tmp_path) -> None:
    """The override applies only to missing identity. A row with no
    capability stays skipped."""
    row = json.dumps({"timestamp": 1780000000})
    path = _write(tmp_path, "g.jsonl", [row])
    result = ingest(path, agent_id="stdio-session-1")

    assert result.actions == []
    assert result.skipped[0].reason == "no capability/tool name"


# -------------------------------------------------------- housekeeping


def test_epoch_millis_are_recognized() -> None:
    seconds = parse_timestamp(1780000000)
    millis = parse_timestamp(1780000000000)
    assert seconds == millis


def test_file_order_is_preserved(tmp_path) -> None:
    rows = [
        {"agent_id": "a1", "capability": f"cap{i}", "timestamp": 1780000000 - i}
        for i in range(5)
    ]
    path = _write(tmp_path, "g.jsonl", [json.dumps(r) for r in rows])
    result = ingest(path)

    assert [a.capability for a in result.actions] == \
           ["cap0", "cap1", "cap2", "cap3", "cap4"]


def test_time_span_reflects_the_data_not_the_order(tmp_path) -> None:
    rows = [
        {"agent_id": "a1", "capability": "c", "timestamp": 1780000500},
        {"agent_id": "a1", "capability": "c", "timestamp": 1780000000},
    ]
    path = _write(tmp_path, "g.jsonl", [json.dumps(r) for r in rows])
    span = ingest(path).time_span()

    assert span == (1780000000.0, 1780000500.0)


def test_unknown_format_is_a_usage_error(tmp_path) -> None:
    path = _write(tmp_path, "g.jsonl", ["{}"])
    with pytest.raises(ValueError, match="unknown format"):
        ingest(path, fmt="splunk")


def test_missing_file_is_reported_clearly(tmp_path) -> None:
    with pytest.raises(FileNotFoundError, match="no such log file"):
        ingest(tmp_path / "nope.jsonl")


def test_empty_result_has_defined_behaviour(tmp_path) -> None:
    path = _write(tmp_path, "g.jsonl", [])
    result = ingest(path)

    assert isinstance(result, IngestResult)
    assert result.actions == []
    assert result.coverage == 0.0
    assert result.time_span() is None
    assert result.agents() == []


def test_detect_format_never_returns_auto(tmp_path) -> None:
    for name, lines in (
        ("m.jsonl", MCP_LINES),
        ("e.jsonl", ["{}"]),
        ("blank.jsonl", []),
    ):
        assert detect_format(_write(tmp_path, name, lines)) != "auto"


def test_actions_are_well_formed_agent_actions(tmp_path) -> None:
    path = _write(tmp_path, "mcp.jsonl", MCP_LINES)
    for action in ingest(path).actions:
        assert isinstance(action, AgentAction)
        assert action.agent_id and action.capability
        assert action.context["source_format"] == "mcp"
        assert action.context["source_line"] > 0


def test_source_outcome_is_preserved_without_claiming_execution(tmp_path) -> None:
    row = {
        "agent_id": "a1",
        "capability": "web_search",
        "timestamp": 1780000000,
        "outcome": "allowed",
    }
    path = _write(tmp_path, "g.jsonl", [json.dumps(row)])

    action = ingest(path).actions[0]

    assert action.context["reported_outcome"] == "allowed"


def test_privatevault_sqlite_history_is_read_read_only(tmp_path) -> None:
    path = tmp_path / "history.db"
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE records (seq INTEGER PRIMARY KEY, body TEXT NOT NULL)"
    )
    rows = [
        {
            "agent_id": "a1",
            "capability": "crm.read_contact",
            "timestamp": 1780000000.25,
            "drift_score": 0.0,
        },
        {
            "agent_id": "a1",
            "capability": "payments.drain_account",
            "timestamp": 1780000001.5,
            "drift_score": 0.9,
        },
    ]
    connection.executemany(
        "INSERT INTO records(seq, body) VALUES (?, ?)",
        [(index, json.dumps(row)) for index, row in enumerate(rows, 1)],
    )
    connection.commit()
    connection.close()

    result = ingest(path)

    assert result.source_format == "sqlite"
    assert result.coverage == 1.0
    assert [action.capability for action in result.actions] == [
        "crm.read_contact",
        "payments.drain_account",
    ]
