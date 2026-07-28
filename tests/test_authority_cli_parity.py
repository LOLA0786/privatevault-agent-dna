"""The runtime-coupled authority CLI must expose the runtime result faithfully."""

# ruff: noqa: F811 - imported pytest fixture name is injected as a parameter

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from agent_dna.authority_v01 import verify_receipt
from tests.test_authority_v01 import artifacts as _artifacts_fixture  # noqa: F401

TOOL = Path("tools/pv_authority_cli.py")


def test_authority_cli_matches_runtime_result(
    tmp_path: Path,
    _artifacts_fixture: dict,
) -> None:
    receipt_path = tmp_path / "receipt.json"
    bundle_path = tmp_path / "trust-bundle.json"
    result_path = tmp_path / "result.json"

    receipt = _artifacts_fixture["receipt"]
    bundle = _artifacts_fixture["bundle"]

    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

    process = subprocess.run(
        [
            sys.executable,
            str(TOOL),
            "verify",
            str(receipt_path),
            str(bundle_path),
            "--json",
            str(result_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert process.returncode == 0, process.stdout + process.stderr

    cli_result = json.loads(result_path.read_text(encoding="utf-8"))
    runtime_result = verify_receipt(receipt, bundle).to_dict()

    assert cli_result == runtime_result
