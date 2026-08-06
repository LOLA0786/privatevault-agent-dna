"""
END-TO-END: everything built in Steps 1-9, one pipeline.

  AgentAction stream (compromised agent)
        |
  DecisionEngine          precedence: invariant > authorization > drift > allow
        |
  RuntimeMonitor          enforcing streaming path; probes don't shift baseline
        |
  DecisionRecorder        sealed, hash-chained DecisionRecords
        |
  DecisionStore           append-only JSONL on disk
        |
  report_outcome          anchored ExecutionEvents (executor feedback)
        |
  DecisionGraph           queryable lineage / blocked / divergence
        |
  tools/verify_records.py stdlib-only auditor, no package import
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

from runtime_demo import banner, synthetic_compromised_trace, train

from agent_dna.decision import Decision, DecisionEngine
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.decision_store import DecisionStore
from agent_dna.runtime import RuntimeMonitor

ROOT = Path(__file__).resolve().parent.parent
VERIFIER = ROOT / "tools" / "verify_records.py"


class Invariants:
    """Behavioral contract: this agent must never bulk-export storage."""

    def validate(self, capability, previous):
        class R:
            pass

        r = R()
        r.violated = capability == "storage.bulk_export"
        r.message = (
            "invariant: storage.bulk_export is contractually forbidden"
            if r.violated
            else ""
        )
        return r


class Authorizer:
    """Approved grants: CRM + email only. Payments has no grant."""

    GRANTED = {
        "crm.read_contact",
        "crm.enrich_contact",
        "crm.update_contact",
        "email.send",
    }

    def is_authorized(self, agent_id, capability):
        return capability in self.GRANTED


def run_verifier(path):
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(path)],
        capture_output=True,
        text=True,
    )
    verdict = [line for line in proc.stdout.splitlines() if line.startswith("VERDICT")]
    fails = [line for line in proc.stdout.splitlines() if "FAIL " in line]
    for line in fails[:3]:
        print(line)
    print(verdict[0] if verdict else "no verdict")
    return proc.returncode


def main():
    workdir = Path(tempfile.mkdtemp(prefix="pv_demo_"))
    log = workdir / "decisions.jsonl"

    # ---- assemble the full stack -------------------------------------
    scorer = train()
    store = DecisionStore(log)
    recorder = DecisionRecorder(store=store)
    engine = DecisionEngine(
        scorer=scorer,
        invariants=Invariants(),
        authorizer=Authorizer(),
    )
    monitor = RuntimeMonitor(engine, recorder=recorder)

    # ---- 1. live enforcement -----------------------------------------
    banner("1. LIVE ENFORCEMENT (compromised agent stream)")
    decided = []
    for action in synthetic_compromised_trace().actions:
        result = monitor.process(action)
        rec = list(recorder.graph)[-1]
        decided.append((rec, result))
        print(
            f"{action.capability:<28}"
            f" {result.decision.value.upper():<17}"
            f" trigger={result.triggered_by:<13}"
            f" drift={result.drift_score:.2f}"
        )

    # ---- 2. executor feedback ------------------------------------------
    banner("2. EXECUTOR FEEDBACK (anchored ExecutionEvents)")
    for rec, result in decided:
        status = "ok" if result.decision == Decision.ALLOW else "refused"
        ev = recorder.report_outcome(rec.decision_id, status)
        print(f"{rec.capability:<28} outcome={status:<8} anchor={ev.prev_hash[:10]}..")

    g = recorder.graph

    # ---- 3. queries -----------------------------------------------------
    banner("3. QUERY THE DECISION GRAPH")
    print("blocked:")
    for r in g.find_blocked():
        print(f"  {r.capability:<28} {r.reason}")
    print("required approval:")
    for r in g.find_requires_approval():
        print(f"  {r.capability:<28} trigger={r.triggered_by}")
    print("divergent (BLOCK that executed anyway):", len(g.find_divergent()))

    # ---- 4. lineage -------------------------------------------------------
    banner("4. LINEAGE (root -> last decision, hash-chained)")
    last = list(g)[-1]
    for step in g.lineage(last.decision_id):
        print(f"{step.capability:<28} {step.decision:<17} {step.record_hash[:12]}..")

    # ---- 5. integrity, in memory and on disk ----------------------------
    banner("5. CHAIN INTEGRITY")
    print(f"in-memory verify_all : {g.verify_all()}")
    print(f"on disk              : {log}")
    print(f"records persisted    : {len(log.read_text().splitlines())}")
    print("independent verifier :")
    run_verifier(log)

    # ---- 6. attack the log ------------------------------------------------
    banner("6. ATTACK: flip the BLOCK to ALLOW in the log file")
    tampered = workdir / "tampered.jsonl"
    lines = []
    for line in log.read_text().splitlines():
        d = json.loads(line)
        if d.get("kind") == "decision" and d.get("decision") == "block":
            d["decision"] = "allow"
            print(f"flipped: {d['capability']}")
        lines.append(json.dumps(d, sort_keys=True, separators=(",", ":")))
    tampered.write_text("\n".join(lines) + "\n")
    run_verifier(tampered)

    banner("7. ATTACK: delete the refusal from the log file")
    deleted = workdir / "deleted.jsonl"
    kept = [
        line
        for line in log.read_text().splitlines()
        if json.loads(line).get("decision") != "block"
    ]
    deleted.write_text("\n".join(kept) + "\n")
    run_verifier(deleted)

    banner("SUMMARY")
    print(
        "The runtime refused in-stream; the refusal is queryable with\n"
        "full lineage; the log is independently verifiable; and both\n"
        "falsifying and deleting the refusal are caught by a stdlib\n"
        "script with zero trust in this codebase."
    )


if __name__ == "__main__":
    main()
