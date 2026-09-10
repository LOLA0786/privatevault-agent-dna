"""
Public MCP server exposing ONLY the independent DRP verifier as a
tool -- no proprietary engine logic, no trained scorer, no
precedence chain. This is the part of PrivateVault that is already
fully public (drp-spec, Apache-2.0), packaged as an MCP tool so any
MCP client can verify a DRP-format audit log without cloning any
repo or trusting any of PrivateVault's own code.

Deliberately calls tools/verify_records.py as a SUBPROCESS, not as
an imported function. This guarantees the MCP tool runs the exact
same unmodified chain-verification path a human would run from the
command line -- zero risk of the MCP wrapper's logic silently
diverging from the real public verifier over time.

Run standalone: python -m agent_dna.mcp_public_verifier
Requires: pip install mcp

This server does NOT require the rest of the agent_dna package's
engine dependencies -- it needs only the mcp package and Python's
standard library for chain verification. Trusted-signature mode is not exposed by this MCP wrapper.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from mcp.server.mcpserver import MCPServer

VERIFIER_PATH = Path(__file__).resolve().parent.parent / "tools" / "verify_records.py"

mcp = MCPServer("privatevault-drp-verifier")


@mcp.tool()
def pv_verify_records(jsonl_content: str) -> dict[str, Any]:
    """Independently verify a DRP (Decision Runtime Protocol) audit
    log. Pass the raw JSONL content of a decision/execution log as a
    string. Runs the public verifier in standard-library chain-only mode
    (tools/verify_records.py) unmodified as a subprocess -- checks
    record-hash integrity, per-agent chain continuity, execution
    anchoring, edge consistency, and enforcement divergence (a BLOCK
    decision whose action executed anyway).

    Returns the verifier's exit code (0 = PASS, 1 = FAIL), the full
    printed output, and a parsed pass/fail summary."""
    if not VERIFIER_PATH.exists():
        return {
            "error": f"verifier script not found at {VERIFIER_PATH}",
            "passed": False,
        }

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
    ) as f:
        f.write(jsonl_content)
        temp_path = f.name

    try:
        proc = subprocess.run(
            [sys.executable, str(VERIFIER_PATH), temp_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
    finally:
        Path(temp_path).unlink(missing_ok=True)

    output = proc.stdout.strip()
    passed = proc.returncode == 0 and "VERDICT: PASS" in output

    return {
        "passed": passed,
        "exit_code": proc.returncode,
        "output": output,
        "stderr": proc.stderr.strip() if proc.stderr else None,
    }


if __name__ == "__main__":
    mcp.run()
