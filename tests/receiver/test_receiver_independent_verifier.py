"""The receiver receipt chain verifies without importing agent_dna.

Claims → tests:
  - Standalone canonicalization equals RFC 8785 for receipts
    → test_standalone_canonical_matches_runtime
  - The CLI, run in a subprocess with an empty PYTHONPATH and no agent_dna
    import, verifies a real ledger with signatures, and detects tampering
    → test_cli_verifies_real_ledger_in_isolation, test_cli_detects_tamper
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from agent_dna.authority_v01 import canonicalize
from agent_dna.receiver.permit_header import PERMIT_HEADER, encode_permit_header

from ._world import METHOD, NOW, PARAMETERS, PATH, RECEIVER, World, wire_for

TOOL = Path(__file__).resolve().parents[2] / "tools" / "verify_receiver_receipts.py"


def _load_tool():
    import importlib.util

    spec = importlib.util.spec_from_file_location("verify_receiver_receipts", TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _populate(w):
    permit = w.permit()
    for headers in ([], [(PERMIT_HEADER, encode_permit_header(permit))]) * 2:
        w.gate.check(
            method=METHOD,
            path=PATH,
            headers=headers,
            body=wire_for(PARAMETERS),
            received_at=NOW,
        )


def _run(*args):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["PYTHONPATH"] = ""
    return subprocess.run(
        [sys.executable, "-I", str(TOOL), *args],
        capture_output=True,
        text=True,
        env=env,
        cwd="/",
        check=False,
    )


def test_standalone_canonical_matches_runtime(tmp_path):
    tool = _load_tool()
    w = World(tmp_path)
    _populate(w)
    for receipt in w.ledger.iter_receipts():
        assert tool.canonical(receipt) == canonicalize(receipt)


def test_cli_verifies_real_ledger_in_isolation(tmp_path):
    w = World(tmp_path)
    _populate(w)
    result = _run(
        "--db",
        str(w.ledger_path),
        "--receiver-id",
        RECEIVER,
        "--receiver-key",
        f"bank-receiver-01={w.gate.receipt_public_key}",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "OK 4 receipts (1 admitted, 3 refused), mode=chain+signatures" in (
        result.stdout
    )


def test_cli_detects_tamper(tmp_path):
    w = World(tmp_path)
    _populate(w)
    conn = sqlite3.connect(w.ledger_path)
    raw = conn.execute(
        "SELECT receipt_json FROM receiver_receipts WHERE sequence = 2"
    ).fetchone()[0]
    receipt = json.loads(raw)
    receipt["wire_bytes_length"] = 1
    conn.execute(
        "UPDATE receiver_receipts SET receipt_json = ? WHERE sequence = 2",
        (json.dumps(receipt),),
    )
    conn.commit()
    conn.close()
    result = _run(
        "--db",
        str(w.ledger_path),
        "--receiver-id",
        RECEIVER,
        "--receiver-key",
        f"bank-receiver-01={w.gate.receipt_public_key}",
    )
    assert result.returncode == 1
    assert "signature invalid" in result.stdout
    assert "does not link" in result.stdout
