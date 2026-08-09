#!/usr/bin/env python3
"""Run an in-process PrivateVault platform demo (auth on, ops surfaces live).

Shows the self-hosted platform path without claiming SOC 2 / ISO certification
or multi-tenant SaaS. Exit 0 only when allow → block → verify → metrics hold.
"""

from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def main() -> int:
    from fastapi.testclient import TestClient

    from agent_dna.apikeys import generate_key

    tmp = Path(tempfile.mkdtemp(prefix="pv-platform-"))
    op = generate_key("payments-agent", "full")
    au = generate_key("auditor", "audit")
    keys = tmp / "keys.json"
    keys.write_text(
        json.dumps(
            {
                op["hash"]: {"name": op["name"], "scope": "full"},
                au["hash"]: {"name": au["name"], "scope": "audit"},
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    import os

    os.environ["PV_DB_PATH"] = str(tmp / "platform.db")
    os.environ["PV_API_KEYS_FILE"] = str(keys)
    os.environ.pop("PV_ALLOW_NO_AUTH", None)

    import importlib

    import api.server as server

    importlib.reload(server)

    print("PrivateVault platform demo")
    print("=========================")
    print(f"workspace: {tmp}")
    print(f"operator key (payments-agent / full): {op['key']}")
    print(f"auditor key (auditor / audit):        {au['key']}")
    print()

    with TestClient(server.app) as client:
        health = client.get("/health").json()
        ready = client.get("/ready").json()
        root = client.get("/").json()
        print(f"health:  {health}")
        print(f"ready:   {ready}")
        print(f"product: {root.get('product')} ({root.get('category')})")
        print(f"certification claim: {root.get('certification')}")
        print()

        op_h = {"X-API-Key": op["key"]}
        allow = client.post(
            "/v1/decide",
            headers=op_h,
            json={
                "agent_id": "payments-agent",
                "capability": "crm.read_contact",
                "timestamp": time.time(),
            },
        )
        print(f"decide ALLOW  -> HTTP {allow.status_code} {allow.json()['decision']}")

        block = client.post(
            "/v1/decide",
            headers=op_h,
            json={
                "agent_id": "payments-agent",
                "capability": "payments.drain_account",
                "timestamp": time.time(),
                "arguments": {"amount": 9_999_999},
            },
        )
        print(
            f"decide BLOCK? -> HTTP {block.status_code} "
            f"{block.json().get('decision')} ({block.json().get('triggered_by')})"
        )

        audit_denied = client.post(
            "/v1/decide",
            headers={"X-API-Key": au["key"]},
            json={
                "agent_id": "auditor",
                "capability": "crm.read_contact",
                "timestamp": time.time(),
            },
        )
        print(f"auditor decide rejected -> HTTP {audit_denied.status_code}")

        verify = client.get("/v1/verify", headers={"X-API-Key": au["key"]})
        print(f"auditor verify -> HTTP {verify.status_code} body={verify.json()}")

        export = client.get("/v1/audit/export", headers={"X-API-Key": au["key"]})
        export_path = tmp / "audit.jsonl"
        export_path.write_bytes(export.content)
        print(f"audit export -> {export_path} ({len(export.content)} bytes)")

        ops = client.get("/v1/ops/summary", headers={"X-API-Key": au["key"]}).json()
        print(f"ops summary -> {json.dumps(ops['metrics'], sort_keys=True)}")

        metrics = client.get("/metrics")
        print(f"prometheus -> HTTP {metrics.status_code}")
        for line in metrics.text.splitlines():
            if line.startswith("pv_"):
                print(f"  {line}")

    import subprocess

    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "verify_records.py"), str(export_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    print()
    print("independent verifier:")
    print(proc.stdout or proc.stderr)
    if proc.returncode != 0:
        print("FAIL: chain verification", file=sys.stderr)
        return 1
    if allow.status_code != 200:
        print("FAIL: expected allow", file=sys.stderr)
        return 1
    if block.status_code not in (202, 403):
        print("FAIL: expected non-allow for novel capability", file=sys.stderr)
        return 1
    if audit_denied.status_code != 401:
        print("FAIL: audit key must not enforce", file=sys.stderr)
        return 1
    print()
    print("PLATFORM DEMO OK — self-hosted decision-security platform surfaces green.")
    print("Not claimed: SOC 2, ISO 27001, multi-tenant SaaS, horizontal scale.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
