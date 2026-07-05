#!/usr/bin/env python3
"""
Independent verifier for decision/execution JSONL audit files.

Uses ONLY the Python standard library and does NOT import agent_dna.

Checks:
  1. Every line is valid JSON.
  2. Every record's record_hash equals sha256 of its canonical payload
     (all fields except record_hash, sorted keys, compact separators).
  3. kind=="decision": per agent, in file order, prev_hash equals the
     previous decision's record_hash (genesis = 64 zeros).
  4. kind=="execution": prev_hash equals the record_hash of the
     referenced decision (anchor binding); decision must appear
     earlier in the file; at most one execution event per decision.
  5. Edge consistency: "follows" target == parent_decision;
     "resulted_in" target == decision_ref.
  6. ENFORCEMENT DIVERGENCE: an execution event with status "ok"
     whose decision was "block" fails verification — the runtime
     refused and the world executed anyway.

Exit codes: 0 pass, 1 fail, 2 usage.
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
    chains = {}            # agent_id -> expected prev_hash (decisions only)
    decisions = {}         # decision_id -> {"hash": .., "decision": ..}
    executed = set()       # decision_ids that already have an execution event
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

            pv = rec.get("protocol_version")
            if pv != "drp/0.1":
                failures.append(
                    f"line {lineno}: protocol_version {pv!r} is not drp/0.1"
                )

            kind = rec.get("kind", "decision")
            stored = rec.get("record_hash", "")
            computed = compute_hash(rec)
            if stored != computed:
                failures.append(
                    f"line {lineno}: record_hash mismatch "
                    f"(stored {stored[:12]}.., computed {computed[:12]}..)"
                )

            if kind == "decision":
                rid = rec.get("decision_id", f"<line {lineno}>")
                agent = rec.get("agent_id", "<missing>")

                expected_prev = chains.get(agent, GENESIS_HASH)
                if rec.get("prev_hash") != expected_prev:
                    failures.append(
                        f"line {lineno} [{rid}]: chain break for agent "
                        f"{agent!r}"
                    )
                chains[agent] = stored
                decisions[rid] = {
                    "hash": stored,
                    "decision": rec.get("decision"),
                }

                for edge in rec.get("edges", []):
                    if edge.get("type") == "follows":
                        if edge.get("target") != rec.get("parent_decision"):
                            failures.append(
                                f"line {lineno} [{rid}]: follows edge "
                                "target != parent_decision"
                            )

            elif kind == "execution":
                eid = rec.get("event_id", f"<line {lineno}>")
                dref = rec.get("decision_ref")

                if dref not in decisions:
                    failures.append(
                        f"line {lineno} [{eid}]: execution references "
                        f"unknown/later decision {dref}"
                    )
                else:
                    if rec.get("prev_hash") != decisions[dref]["hash"]:
                        failures.append(
                            f"line {lineno} [{eid}]: anchor mismatch — "
                            "prev_hash != decision record_hash"
                        )
                    if dref in executed:
                        failures.append(
                            f"line {lineno} [{eid}]: duplicate execution "
                            f"event for decision {dref}"
                        )
                    executed.add(dref)

                    # 6. enforcement divergence
                    if (
                        decisions[dref]["decision"] == "block"
                        and rec.get("status") == "ok"
                    ):
                        failures.append(
                            f"line {lineno} [{eid}]: ENFORCEMENT DIVERGENCE "
                            f"— decision {dref} was BLOCK but execution "
                            "status is ok"
                        )

                for edge in rec.get("edges", []):
                    if edge.get("type") == "resulted_in":
                        if edge.get("target") != dref:
                            failures.append(
                                f"line {lineno} [{eid}]: resulted_in edge "
                                "target != decision_ref"
                            )
            else:
                failures.append(f"line {lineno}: unknown kind {kind!r}")

    print(f"records checked : {total}")
    print(f"agents          : {len(chains)}")
    print(f"decisions       : {len(decisions)}")
    print(f"executions      : {len(executed)}")
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
