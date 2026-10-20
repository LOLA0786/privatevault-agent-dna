#!/usr/bin/env python3
"""Convert a PrivateVault audit export into SIEM events.

Input: the canonical JSONL from ``GET /v1/audit/export`` (or
``store.export_jsonl``). Output, one event per decision record:

* ``--format ecs`` (default): Elastic Common Schema NDJSON, accepted by
  Elastic, OpenSearch, Splunk HEC (``_json`` sourcetype), Microsoft Sentinel
  and Google SecOps custom parsers.
* ``--format cef``: ArcSight Common Event Format lines (QRadar, ArcSight,
  syslog collectors).

Every event carries the record's ``record_hash`` and ``prev_hash`` so a
SOC analyst can go from an alert to the sealed record and verify it with
``tools/verify_records.py``. ``--after HASH`` emits only records after the
one with that hash, for incremental shipping from a scheduled job. Run the
verifier on the export first: this tool converts, it does not verify.

Standard library only; no network access.

    curl -s -H "X-API-Key: $PV_AUDITOR_KEY" https://pv/v1/audit/export \
      | python tools/siem_export.py --format ecs > pv-events.ndjson
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from typing import Any, TextIO

OUTCOME = {"allow": "success", "block": "failure", "require_approval": "unknown"}
CEF_SEVERITY = {"info": 3, "low": 3, "medium": 5, "high": 8, "critical": 10}


def _records(lines: Iterable[str]) -> Iterator[dict[str, Any]]:
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError as exc:
            raise SystemExit(f"line {n}: not JSON ({exc})") from exc
        if not isinstance(rec, dict) or "record_hash" not in rec:
            raise SystemExit(f"line {n}: not a PrivateVault record")
        yield rec


def _iso(ts: Any) -> str | None:
    try:
        return (
            datetime.fromtimestamp(float(ts), UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
    except (TypeError, ValueError, OverflowError):
        return None


def to_ecs(rec: dict[str, Any]) -> dict[str, Any]:
    decision = rec.get("decision")
    return {
        "@timestamp": _iso(rec.get("timestamp")),
        "ecs": {"version": "8.11.0"},
        "event": {
            "kind": "event",
            "category": ["iam", "process"]
            if str(rec.get("capability", "")).startswith("shell.")
            else ["iam"],
            "type": ["allowed"]
            if decision == "allow"
            else ["denied"]
            if decision == "block"
            else ["info"],
            "action": rec.get("capability"),
            "outcome": OUTCOME.get(str(decision), "unknown"),
            "reason": rec.get("reason"),
            "severity": CEF_SEVERITY.get(str(rec.get("severity")), 3),
            "id": rec.get("decision_id"),
            "provider": "privatevault",
            "dataset": "privatevault.decision",
            "hash": rec.get("record_hash"),
        },
        "rule": {"id": rec.get("policy_id"), "name": rec.get("triggered_by")},
        "user": {"name": rec.get("agent_id")},
        "observer": {
            "vendor": "PrivateVault",
            "product": "agent-dna",
            "type": "decision-security",
        },
        "privatevault": {
            k: rec.get(k)
            for k in (
                "decision",
                "triggered_by",
                "kind",
                "protocol_version",
                "record_hash",
                "prev_hash",
                "parent_decision",
                "arguments_digest",
                "approval_ref",
                "receipt_ref",
                "outcome",
                "drift_score",
                "request_id",
            )
        },
    }


def _cef_escape(value: Any, header: bool = False) -> str:
    s = "" if value is None else str(value)
    s = s.replace("\\", "\\\\").replace("\r", " ").replace("\n", " ")
    return s.replace("|", "\\|") if header else s.replace("=", "\\=")


def to_cef(rec: dict[str, Any]) -> str:
    sev = CEF_SEVERITY.get(str(rec.get("severity")), 3)
    ts = rec.get("timestamp")
    ext = {
        "rt": int(float(ts) * 1000) if isinstance(ts, (int, float)) else None,
        "suser": rec.get("agent_id"),
        "act": rec.get("decision"),
        "outcome": OUTCOME.get(str(rec.get("decision")), "unknown"),
        "reason": rec.get("reason"),
        "cs1Label": "record_hash",
        "cs1": rec.get("record_hash"),
        "cs2Label": "prev_hash",
        "cs2": rec.get("prev_hash"),
        "cs3Label": "triggered_by",
        "cs3": rec.get("triggered_by"),
        "cs4Label": "policy_id",
        "cs4": rec.get("policy_id"),
        "externalId": rec.get("decision_id"),
    }
    for n in range(1, 5):  # a label without its value is noise
        if ext.get(f"cs{n}") is None:
            ext.pop(f"cs{n}Label", None)
    body = " ".join(f"{k}={_cef_escape(v)}" for k, v in ext.items() if v is not None)
    head = "|".join(
        _cef_escape(x, header=True)
        for x in (
            "CEF:0",
            "PrivateVault",
            "agent-dna",
            "1",
            f"decision:{rec.get('decision')}",
            f"{rec.get('capability')} {rec.get('decision')}",
            sev,
        )
    )
    return f"{head}|{body}"


def convert(
    src: TextIO, dst: TextIO, fmt: str = "ecs", after: str | None = None
) -> int:
    emitting = after is None
    n = 0
    for rec in _records(src):
        if not emitting:
            emitting = rec.get("record_hash") == after
            continue
        line = json.dumps(to_ecs(rec), sort_keys=True) if fmt == "ecs" else to_cef(rec)
        dst.write(line + "\n")
        n += 1
    if not emitting:
        raise SystemExit(f"--after {after}: no record with that hash in the input")
    return n


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("input", nargs="?", default="-", help="audit JSONL (default stdin)")
    ap.add_argument("--format", choices=("ecs", "cef"), default="ecs")
    ap.add_argument("--after", help="emit only records after this record_hash")
    args = ap.parse_args(argv)
    src = sys.stdin if args.input == "-" else open(args.input, encoding="utf-8")
    try:
        n = convert(src, sys.stdout, args.format, args.after)
    finally:
        if src is not sys.stdin:
            src.close()
    print(f"{n} events", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
