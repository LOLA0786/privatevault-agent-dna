"""Inventory classification must never infer safety from ambiguous names."""

from __future__ import annotations

import pytest

from agent_dna.scan.ingest import IngestResult
from agent_dna.scan.inventory import (
    IRREVERSIBLE,
    MUTATING,
    READ_ONLY,
    UNKNOWN,
    build_inventory,
    classify,
)
from agent_dna.trace import AgentAction


def _action(capability: str, *, arguments: dict | None = None) -> AgentAction:
    return AgentAction(
        agent_id="agent-1",
        capability=capability,
        timestamp=1.0,
        arguments=arguments or {},
    )


@pytest.mark.parametrize(
    ("capability", "expected"),
    [
        ("web_search", READ_ONLY),
        ("tool_search", UNKNOWN),
        ("crm.read_contact", READ_ONLY),
        ("crm.update_contact", MUTATING),
        ("payments.get_balance", READ_ONLY),
        ("payments.transfer", IRREVERSIBLE),
        ("payments.drain_account", IRREVERSIBLE),
        ("wire.get_status", READ_ONLY),
        ("settle.view_queue", READ_ONLY),
        ("email.send", IRREVERSIBLE),
        ("storage.bulk_export", IRREVERSIBLE),
    ],
)
def test_exact_manifest_contracts(capability: str, expected: str) -> None:
    result = classify(_action(capability))

    assert result.effect == expected
    assert result.basis == "manifest"


@pytest.mark.parametrize(
    "capability",
    [
        "fetch_and_delete",
        "database_search_delete",
        "search_delete",
        "delete_file",
        "file_delete",
        "artifact.describe_release",
        "report.read_export",
        "email.send_draft",
        "payments.read_export",
    ],
)
def test_ambiguous_or_unregistered_names_are_never_assumed_safe(
    capability: str,
) -> None:
    result = classify(_action(capability))

    assert result.effect == UNKNOWN


def test_shell_command_evidence_overrides_shell_capability() -> None:
    assert (
        classify(_action("bash", arguments={"cmd": "git status"})).effect == READ_ONLY
    )
    assert (
        classify(
            _action("bash", arguments={"cmd": "git push --force origin main"})
        ).effect
        == IRREVERSIBLE
    )
    assert (
        classify(
            _action("bash", arguments={"cmd": "custom-tool --do-something"})
        ).effect
        == UNKNOWN
    )


def test_build_inventory_uses_manifest_and_preserves_unknown() -> None:
    result = IngestResult(
        actions=[
            _action("payments.get_balance"),
            _action("payments.transfer"),
            _action("fetch_and_delete"),
        ],
        source_format="generic",
        source_path="history.jsonl",
        lines_read=3,
    )

    report = build_inventory(result)

    assert report.by_effect() == {
        IRREVERSIBLE: 1,
        MUTATING: 0,
        UNKNOWN: 1,
        READ_ONLY: 1,
    }
    assert report.agents["agent-1"].actions == 3
