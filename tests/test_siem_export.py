"""tools/siem_export.py: audit export -> ECS / CEF (enterprise hardening)."""

from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "siem_export", ROOT / "tools" / "siem_export.py"
)
siem = importlib.util.module_from_spec(spec)
spec.loader.exec_module(siem)
CLEAN = (ROOT / "spec" / "test-vectors" / "clean.jsonl").read_text()


def test_ecs_one_event_per_record_with_hashes():
    out = io.StringIO()
    n = siem.convert(io.StringIO(CLEAN), out, "ecs")
    lines = out.getvalue().splitlines()
    records = [json.loads(x) for x in CLEAN.splitlines() if x.strip()]
    assert n == len(lines) == len(records)
    ev = json.loads(lines[0])
    assert ev["event"]["hash"] == records[0]["record_hash"]
    assert ev["privatevault"]["prev_hash"] == records[0]["prev_hash"]
    assert ev["@timestamp"].endswith("Z")
    assert ev["event"]["outcome"] == {"allow": "success", "block": "failure"}.get(
        records[0]["decision"], "unknown"
    )


def test_cef_header_and_escaping():
    rec = {
        "record_hash": "h1",
        "prev_hash": "h0",
        "decision": "block",
        "capability": "shell.exec",
        "severity": "critical",
        "reason": "a=b | c\nd",
        "timestamp": 1.5,
        "agent_id": "coder",
    }
    line = siem.to_cef(rec)
    assert line.startswith(
        "CEF:0|PrivateVault|agent-dna|1|decision:block|shell.exec block|10|"
    )
    assert "reason=a\\=b | c d" in line and "\n" not in line
    assert "cs1=h1" in line and "rt=1500" in line


def test_after_cursor_is_incremental():
    records = [json.loads(x) for x in CLEAN.splitlines() if x.strip()]
    out = io.StringIO()
    n = siem.convert(io.StringIO(CLEAN), out, "ecs", after=records[0]["record_hash"])
    assert n == len(records) - 1
    with pytest.raises(SystemExit):
        siem.convert(io.StringIO(CLEAN), io.StringIO(), "ecs", after="nope")


def test_rejects_non_records():
    with pytest.raises(SystemExit):
        siem.convert(io.StringIO('{"x":1}\n'), io.StringIO())
