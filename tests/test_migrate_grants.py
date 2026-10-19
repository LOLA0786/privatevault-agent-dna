"""Legacy profiles/grants.json -> PV_GRANTS_FILE (external retest 3)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from agent_dna.composition import _load_grants
from tools.migrate_grants import migrate

REPO = Path(__file__).resolve().parents[1]
LEGACY = REPO / "profiles" / "grants.json"


def test_loader_names_the_legacy_format_and_the_tool():
    with pytest.raises(ValueError) as exc:
        _load_grants(str(LEGACY))
    msg = str(exc.value)
    assert "legacy per-agent grants format" in msg
    assert "tools/migrate_grants.py" in msg


def test_migrated_repo_file_loads(tmp_path):
    out = tmp_path / "grants.json"
    r = subprocess.run(
        [sys.executable, "tools/migrate_grants.py", str(LEGACY), "--environment", "prod", "--out", str(out)],
        cwd=REPO, capture_output=True, text=True,
    )
    assert r.returncode == 0, r.stderr
    entries = json.loads(out.read_text())
    assert {(e["agent_id"], e["capability"]) for e in entries} == {
        ("sales-agent-01", "payments.initiate_wire"),
        ("sales-agent-01", "storage.bulk_export"),
    }
    assert {e["granted_by"] for e in entries} == {"Operations", "Security Team"}
    reg = _load_grants(str(out))
    assert reg.authorization_mode == "grants_file"


def test_other_environment_is_not_widened():
    legacy = {"a": {"x.y": {"capability": "x.y", "environment": "staging", "version": "*"}}}
    grants, notes = migrate(legacy, "prod")
    assert grants == [] and "skipped" in notes[0]


def test_version_pin_refused_unless_allowed():
    legacy = {"a": {"x.y": {"capability": "x.y", "environment": "prod", "version": "1.2"}}}
    with pytest.raises(ValueError, match="version"):
        migrate(legacy, "prod")
    grants, notes = migrate(legacy, "prod", allow_version_pins=True)
    assert grants[0]["capability"] == "x.y" and "dropped version pin" in notes[0]
