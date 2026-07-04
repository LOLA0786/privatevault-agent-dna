#!/usr/bin/env python3
"""
Independent verifier for DecisionRecord JSONL files.

Uses ONLY the Python standard library and does NOT import agent_dna.
An auditor can run this against a decision log with nothing but this
file and Python 3.

Checks, per file:
  1. Every line is valid JSON.
  2. Every record's record_hash equals sha256 of its canonical payload
     (all fields except record_hash, JSON-serialized with sorted keys
     and compact separators).
  3. Per agent, in file order: each record's prev_hash equals the
     previous record's record_hash; first record chains from the
     genesis hash (64 zeros).
  4. Every "follows" edge target equals parent_decision.

Exit codes: 0 = all checks pass, 1 = verification failure, 2 = usage.

Usage: python3 verify_records.py <records.jsonl>
"""

import hashlib
import json
import sys

GENESIS_HASH = "0" * 64


def compute_hash(record: dict) -> str:
    payload = {k: v for k, v in record.items() if k != "record_hash"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def verify(path: str) -> int:
    failures = []
    chains = {}      # agent_id -> expected prev_hash
    total = 0

    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            total += 1

            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                failures.append(f"line {lineno}: invalid JSON")
                continue

            rid = rec.get("decision_id", f"<line {lineno}>")
            agent = rec.get("agent_id", "<missing>")

            # 2. per-record hash
            stored = rec.get("record_hash", "")
            computed = compute_hash(rec)
            if stored != computed:
                failures.append(
                    f"line {lineno} [{rid}]: record_hash mismatch "
                    f"(stored {stored[:12]}.., computed {computed[:12]}..)"
                )

            # 3. per-agent chain
            expected_prev = chains.get(agent, GENESIS_HASH)
            if rec.get("prev_hash") != expected_prev:
                failures.append(
                    f"line {lineno} [{rid}]: chain break for agent "
                    f"{agent!r} (prev_hash != previous record_hash)"
                )
            chains[agent] = stored

            # 4. follows edge consistency
            for edge in rec.get("edges", []):
                if edge.get("type") == "follows":
                    if edge.get("target") != rec.get("parent_decision"):
                        failures.append(
                            f"line {lineno} [{rid}]: follows edge target "
                            "!= parent_decision"
                        )

    print(f"records checked : {total}")
    print(f"agents          : {len(chains)}")
    print(f"failures        : {len(failures)}")
    for msg in failures:
        print(f"  FAIL {msg}")
    print("VERDICT:", "PASS" if not failures else "FAIL")
    return 0 if not failures else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(verify(sys.argv[1]))
