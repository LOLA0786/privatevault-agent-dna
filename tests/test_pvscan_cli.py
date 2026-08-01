"""The standalone inventory must not claim authority or execution proof."""

from __future__ import annotations

import json
from pathlib import Path

from agent_dna.scan import ingest
from agent_dna.scan.inventory import build_inventory
from tools.pvscan import Totals, find_logs, render, to_json


def test_recursive_discovery_ignores_configs_and_tabular_data(
    tmp_path: Path,
) -> None:
    (tmp_path / "session.jsonl").write_text("{}\n", encoding="utf-8")
    (tmp_path / "package.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "transactions.csv").write_text("id,value\n1,2\n", encoding="utf-8")
    (tmp_path / "history.db").write_bytes(b"not a database")

    assert find_logs(tmp_path, 100) == [tmp_path / "session.jsonl"]
    assert find_logs(tmp_path / "transactions.csv", 100) == [
        tmp_path / "transactions.csv"
    ]


def test_report_says_authority_is_not_assessed(tmp_path: Path) -> None:
    path = tmp_path / "session.jsonl"
    path.write_text(
        json.dumps(
            {
                "agent_id": "a1",
                "tool": "web_search",
                "timestamp": 1780000000,
                "outcome": "allowed",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    result = ingest(path)
    totals = Totals()
    totals.absorb(build_inventory(result), result)

    human = render(totals, path)
    machine = to_json(totals, path)

    assert "Not assessed by this dependency-free inventory command" in human
    assert "0 of 1" not in human
    assert machine["authority_evidence_assessed"] is False
    assert "authority_evidence_found" not in machine
    assert machine["reported_outcomes"] == {"allowed": 1}
    assert "Source labels only; not execution proof" in human
