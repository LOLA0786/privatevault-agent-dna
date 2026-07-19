#!/usr/bin/env python3
"""
Independent verifier for decision/execution JSONL audit files.

Uses ONLY the Python standard library and does NOT import agent_dna.

Checks:
  1.  Every line is strict JSON (NaN/Infinity rejected).
  2.  Every record carries EXACTLY the DRP field set for its kind --
      unknown fields and missing fields both fail (a stripped-and-
      rehashed record is internally consistent; the field set is what
      catches it).
  3.  record_hash equals sha256 of the canonical payload (all fields
      except record_hash, sorted keys, compact separators), and both
      record_hash and prev_hash are 64 lowercase hex.
  4.  decision_id and event_id are unique file-wide (duplicates fail;
      references bind to the FIRST occurrence).
  5.  kind=="decision": per agent, in file order, prev_hash equals the
      previous decision's record_hash. The FIRST record of an agent
      establishes that agent's origin: 64 zeros = genesis, anything
      else = external provenance anchor (drp/0.1 anchor rule).
      Anchored agents are REPORTED -- the file proves continuity from
      the anchor; anchor authenticity is attested out of band.
  6.  Lineage: a non-null parent_decision must reference a decision
      seen EARLIER, belonging to the SAME agent, whose record_hash
      equals this record's prev_hash (i.e. the immediate prior
      decision), and exactly one "follows" edge must target it. A null
      parent_decision forbids "follows" edges.
  7.  Enums: decision in {allow, require_approval, block}; execution
      status in {ok, error, refused}.
  8.  kind=="execution": prev_hash equals the referenced decision's
      record_hash; the decision must appear earlier; the execution's
      agent_id must equal the decision's; at most one execution per
      decision; "resulted_in" edges must target decision_ref.
  9.  ENFORCEMENT DIVERGENCE: an execution with status "ok" whose
      decision was "block" fails -- the runtime refused and the world
      executed anyway.

Exit codes: 0 pass, 1 fail, 2 usage.
Usage: python3 verify_records.py <records.jsonl>
"""

import hashlib
import json
import re
import sys

GENESIS_HASH = "0" * 64
HEX64 = re.compile(r"[0-9a-f]{64}\Z")

DECISION_FIELDS = frozenset({
    "kind", "protocol_version", "decision_id", "parent_decision",
    "agent_id", "capability", "decision", "triggered_by", "reason",
    "severity", "drift_score", "evidence", "evidence_strength",
    "arguments_digest", "outcome", "request_id", "goal", "intent",
    "policy_id", "approval_ref", "receipt_ref", "edges", "timestamp",
    "prev_hash", "record_hash",
})
EXECUTION_FIELDS = frozenset({
    "kind", "protocol_version", "event_id", "agent_id", "decision_ref",
    "status", "detail", "edges", "timestamp", "prev_hash", "record_hash",
})
DECISION_ENUM = {"allow", "require_approval", "block"}
STATUS_ENUM = {"ok", "error", "refused"}


def _reject_nonfinite(token):
    raise ValueError(f"non-finite number {token!r} is not valid JSON")


def compute_hash(record: dict) -> str:
    payload = {k: v for k, v in record.items() if k != "record_hash"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def verify(path: str) -> int:
    failures = []
    chains = {}            # agent_id -> expected prev_hash (decisions)
    anchored = {}          # agent_id -> anchor hash (non-genesis origins)
    decisions = {}         # decision_id -> {"hash","decision","agent"} (first occurrence)
    event_ids = set()
    executed = set()       # decision_ids with an execution event
    total = 0

    with open(path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            total += 1

            try:
                rec = json.loads(line, parse_constant=_reject_nonfinite)
            except ValueError as e:
                failures.append(f"line {lineno}: invalid JSON ({e})")
                continue

            pv = rec.get("protocol_version")
            if pv != "drp/0.1":
                failures.append(
                    f"line {lineno}: protocol_version {pv!r} is not drp/0.1"
                )

            kind = rec.get("kind", "decision")
            expected_fields = (
                DECISION_FIELDS if kind == "decision"
                else EXECUTION_FIELDS if kind == "execution"
                else None
            )
            if expected_fields is None:
                failures.append(f"line {lineno}: unknown kind {kind!r}")
                continue

            unknown = set(rec) - expected_fields
            missing = expected_fields - set(rec)
            if unknown:
                failures.append(
                    f"line {lineno}: unknown field(s) {sorted(unknown)}"
                )
            if missing:
                failures.append(
                    f"line {lineno}: missing field(s) {sorted(missing)}"
                )
                continue

            stored = rec.get("record_hash", "")
            prev = rec.get("prev_hash", "")
            for label, value in (("record_hash", stored), ("prev_hash", prev)):
                if not isinstance(value, str) or not HEX64.match(value):
                    failures.append(
                        f"line {lineno}: {label} is not 64 lowercase hex"
                    )

            computed = compute_hash(rec)
            if stored != computed:
                failures.append(
                    f"line {lineno}: record_hash mismatch "
                    f"(stored {stored[:12]}.., computed {computed[:12]}..)"
                )

            if kind == "decision":
                rid = rec.get("decision_id", f"<line {lineno}>")
                agent = rec.get("agent_id", "<missing>")

                if rec.get("decision") not in DECISION_ENUM:
                    failures.append(
                        f"line {lineno} [{rid}]: decision "
                        f"{rec.get('decision')!r} not in {sorted(DECISION_ENUM)}"
                    )

                if rid in decisions:
                    failures.append(
                        f"line {lineno} [{rid}]: duplicate decision_id "
                        "(references bind to the first occurrence)"
                    )
                    continue

                if agent in chains:
                    if prev != chains[agent]:
                        failures.append(
                            f"line {lineno} [{rid}]: chain break for agent "
                            f"{agent!r}"
                        )
                else:
                    # first record for this agent establishes the origin
                    if prev != GENESIS_HASH:
                        anchored[agent] = prev   # drp/0.1 anchor rule
                chains[agent] = stored

                # ---- lineage (P0-4) ----
                parent = rec.get("parent_decision")
                follows = [
                    e for e in rec.get("edges", [])
                    if isinstance(e, dict) and e.get("type") == "follows"
                ]
                if parent is None:
                    if follows:
                        failures.append(
                            f"line {lineno} [{rid}]: follows edge present "
                            "but parent_decision is null"
                        )
                else:
                    pinfo = decisions.get(parent)
                    if pinfo is None:
                        failures.append(
                            f"line {lineno} [{rid}]: parent_decision "
                            f"{parent!r} does not reference an earlier "
                            "decision"
                        )
                    else:
                        if pinfo["agent"] != agent:
                            failures.append(
                                f"line {lineno} [{rid}]: parent_decision "
                                f"{parent!r} belongs to agent "
                                f"{pinfo['agent']!r}, not {agent!r}"
                            )
                        if pinfo["hash"] != prev:
                            failures.append(
                                f"line {lineno} [{rid}]: parent is not the "
                                "immediate prior decision (prev_hash != "
                                "parent record_hash)"
                            )
                    if len(follows) != 1 or follows[0].get("target") != parent:
                        failures.append(
                            f"line {lineno} [{rid}]: exactly one follows "
                            "edge targeting parent_decision is required"
                        )

                decisions[rid] = {
                    "hash": stored,
                    "decision": rec.get("decision"),
                    "agent": agent,
                }

            else:  # execution
                eid = rec.get("event_id", f"<line {lineno}>")
                dref = rec.get("decision_ref")

                if eid in event_ids:
                    failures.append(
                        f"line {lineno} [{eid}]: duplicate event_id"
                    )
                event_ids.add(eid)

                if rec.get("status") not in STATUS_ENUM:
                    failures.append(
                        f"line {lineno} [{eid}]: status "
                        f"{rec.get('status')!r} not in {sorted(STATUS_ENUM)}"
                    )

                if dref not in decisions:
                    failures.append(
                        f"line {lineno} [{eid}]: execution references "
                        f"unknown/later decision {dref}"
                    )
                else:
                    dinfo = decisions[dref]
                    if prev != dinfo["hash"]:
                        failures.append(
                            f"line {lineno} [{eid}]: anchor mismatch — "
                            "prev_hash != decision record_hash"
                        )
                    if rec.get("agent_id") != dinfo["agent"]:
                        failures.append(
                            f"line {lineno} [{eid}]: execution agent_id "
                            f"{rec.get('agent_id')!r} != decision agent "
                            f"{dinfo['agent']!r}"
                        )
                    if dref in executed:
                        failures.append(
                            f"line {lineno} [{eid}]: duplicate execution "
                            f"event for decision {dref}"
                        )
                    executed.add(dref)

                    if (
                        dinfo["decision"] == "block"
                        and rec.get("status") == "ok"
                    ):
                        failures.append(
                            f"line {lineno} [{eid}]: ENFORCEMENT DIVERGENCE "
                            f"— decision {dref} was BLOCK but execution "
                            "status is ok"
                        )

                for edge in rec.get("edges", []):
                    if isinstance(edge, dict) and edge.get("type") == "resulted_in":
                        if edge.get("target") != dref:
                            failures.append(
                                f"line {lineno} [{eid}]: resulted_in edge "
                                "target != decision_ref"
                            )

    print(f"records checked : {total}")
    print(f"agents          : {len(chains)}")
    print(f"anchored agents : {len(anchored)}"
          + (f" ({', '.join(sorted(anchored))})" if anchored else ""))
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
