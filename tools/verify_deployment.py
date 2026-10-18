#!/usr/bin/env python3
"""Verify what a running PrivateVault deployment actually enforces.

A configuration value is a claim; this tool checks the claim and then tests
the behaviour. Standard library only, so it runs from any machine that can
reach the API.

Config checks (GET /v1/runtime):
  - lineage is attached in enforce mode
  - decisions are signed
  - grants come from a file, with durable spend and durable revocation

Behaviour probes (unless --no-probe). Two audit records with the clearly
labelled capabilities ``pv.selftest.initiate`` / ``pv.selftest.approve`` are
written under the probing key's agent:
  1. an approval that names nothing is refused (LINEAGE_APPROVE_UNBOUND)
  2. the initiator approving its own initiate is refused
     (LINEAGE_MAKER_EQUALS_CHECKER)

Exit codes: 0 all checks pass, 1 any check fails, 2 usage / unreachable.
Usage:
  python3 verify_deployment.py --url https://pv.example --api-key KEY --agent-id AGENT
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

Transport = Callable[[str, str, dict[str, Any] | None], tuple[int, Any]]

# Durable stores the runtime reports for grant spend and revocation.
_DURABLE = frozenset({"durable (sqlite)", "durable (postgresql)"})

INITIATE = "pv.selftest.initiate"
APPROVE = "pv.selftest.approve"
LINEAGE = "lineage_invariant"


def http_transport(base_url: str, api_key: str, timeout: float) -> Transport:
    def call(method: str, path: str, body: dict[str, Any] | None) -> tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            base_url.rstrip("/") + path,
            data=data,
            method=method,
            headers={"X-API-Key": api_key, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                return resp.status, json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                return exc.code, json.loads(raw or b"null")
            except ValueError:
                return exc.code, raw.decode("utf-8", "replace")

    return call


def _decide(call: Transport, agent: str, capability: str, lineage=None):
    body: dict[str, Any] = {
        "agent_id": agent,
        "capability": capability,
        "timestamp": time.time(),
        "arguments": {"selftest": True},
    }
    if lineage is not None:
        body["lineage"] = lineage
    return call("POST", "/v1/decide", body)


def run_checks(call: Transport, agent: str, probe: bool) -> list[tuple[str, bool, str]]:
    results: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str) -> None:
        results.append((name, ok, detail))

    status, body = call("GET", "/v1/runtime", None)
    if status != 200 or not isinstance(body, dict):
        check("runtime manifest readable", False, f"HTTP {status}")
        return results
    comp = body.get("composition", {})
    lineage = comp.get("lineage", {})
    check(
        "lineage enforced",
        lineage.get("status") == "enforced" and lineage.get("mode") == "enforce",
        f"status={lineage.get('status')} mode={lineage.get('mode')}",
    )
    signing = comp.get("signing", {})
    check(
        "decisions signed",
        signing.get("status") == "attached",
        str(signing.get("status")),
    )
    auth = comp.get("authorization", {})
    check("grants from file", auth.get("mode") == "grants_file", str(auth.get("mode")))
    check(
        "durable grant spend",
        auth.get("spend") in _DURABLE,
        str(auth.get("spend")),
    )
    check(
        "durable grant revocation",
        auth.get("revocation") in _DURABLE,
        str(auth.get("revocation")),
    )

    if not probe:
        return results
    status, body = _decide(call, agent, APPROVE)
    check(
        "probe: unbound approval refused",
        status == 403
        and isinstance(body, dict)
        and body.get("triggered_by") == LINEAGE
        and "LINEAGE_APPROVE_UNBOUND" in str(body.get("reason")),
        f"HTTP {status} triggered_by={_get(body, 'triggered_by')}",
    )
    status, body = _decide(call, agent, INITIATE)
    record_hash = _get(_get(body, "record"), "record_hash")
    if status not in (200, 202, 403) or not record_hash:
        check("probe: initiate recorded", False, f"HTTP {status}")
        return results
    status, body = _decide(call, agent, APPROVE, {"approves": record_hash})
    check(
        "probe: self-approval refused",
        status == 403
        and isinstance(body, dict)
        and body.get("triggered_by") == LINEAGE
        and "LINEAGE_MAKER_EQUALS_CHECKER" in str(body.get("reason")),
        f"HTTP {status} triggered_by={_get(body, 'triggered_by')}",
    )
    return results


def _get(obj: Any, key: str) -> Any:
    return obj.get(key) if isinstance(obj, dict) else None


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Verify a running PrivateVault deployment.")
    p.add_argument("--url", required=True)
    p.add_argument("--api-key", required=True, help="full-scope key of --agent-id")
    p.add_argument("--agent-id", required=True)
    p.add_argument("--no-probe", action="store_true", help="config checks only")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--json", action="store_true", help="machine-readable output")
    args = p.parse_args(argv)
    call = http_transport(args.url, args.api_key, args.timeout)
    try:
        results = run_checks(call, args.agent_id, probe=not args.no_probe)
    except (urllib.error.URLError, OSError) as exc:
        print(f"unreachable: {exc}", file=sys.stderr)
        return 2
    passed = all(ok for _, ok, _ in results) and bool(results)
    if args.json:
        print(
            json.dumps(
                {
                    "verdict": "PASS" if passed else "FAIL",
                    "checks": [
                        {"check": n, "ok": ok, "detail": d} for n, ok, d in results
                    ],
                },
                indent=2,
            )
        )
    else:
        for name, ok, detail in results:
            print(f"{'PASS' if ok else 'FAIL'}  {name:34s} {detail}")
        print("VERDICT:", "PASS" if passed else "FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
