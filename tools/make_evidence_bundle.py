#!/usr/bin/env python3
"""Build a counterparty evidence bundle.

    python tools/make_evidence_bundle.py [-o evidence-bundle]

Produces a directory an external party can verify in under a minute
with nothing but Python 3 -- no install, no dependency on this
codebase:

    clean.jsonl      a real ledger from the runtime; MUST verify
    divergent.jsonl  same ledger, one execution outcome forged so the
                     runtime's BLOCK is contradicted; MUST fail with
                     ENFORCEMENT DIVERGENCE
    tampered.jsonl   same ledger, one field edited after sealing;
                     MUST fail with a record_hash mismatch
    verify_records.py  the independent verifier (stdlib only)
    README.md          three commands and the expected verdicts
    MANIFEST.sha256    hashes of every file in the bundle

The point of shipping failures alongside the pass: a log that only
ever verifies proves nothing. The bundle demonstrates detection.

Records are produced by driving the real composed runtime, not by
hand-writing JSON -- what the reviewer verifies is what the product
emits.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent_dna.composition import (  # noqa: E402
    RuntimeConfig,
    build_production_runtime,
)
from agent_dna.trace import AgentAction  # noqa: E402

T0 = 1_753_000_000.0

# A small BFSI-shaped session: routine reads, a policy-relevant
# transfer, a forbidden bulk export, and executor feedback for each.
SCENARIO = [
    ("treasury-agent-07", "crm.read_contact", {}, "ok"),
    ("treasury-agent-07", "crm.read_contact", {}, "ok"),
    ("treasury-agent-07", "payments.transfer", {"amount": 4_200_000}, "ok"),
    ("treasury-agent-07", "payments.drain_account", {"amount": 9_900_000}, "refused"),
    ("ops-agent-02", "crm.read_contact", {}, "ok"),
    ("ops-agent-02", "storage.bulk_export", {"rows": 1_400_000}, "refused"),
]

# A customer policy is what produces deterministic BLOCKs in
# production; without one every verdict falls through to the advisory
# drift layer. Shipping the policy with the bundle keeps the ledger
# self-explaining.
POLICY = """version: "1.0"
policies:
  - id: no-account-drain
    capability: payments.drain_account
    outcome: block
    reason: "account drain is forbidden for autonomous agents"
  - id: no-bulk-export
    capability: storage.bulk_export
    outcome: block
    reason: "bulk customer export requires a human data-request ticket"
  - id: transfer-ceiling
    capability: payments.transfer
    outcome: require_approval
    reason: "transfers above the autonomous ceiling need dual control"
    condition:
      field: arguments.amount
      operator: ">"
      value: 1000000
"""


def build_ledger(out: Path) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="pv_bundle_"))
    policy_path = tmp / "policy.yaml"
    policy_path.write_text(POLICY)
    rt = build_production_runtime(
        RuntimeConfig(
            db_path=str(tmp / "pv.db"),
            policy_file=str(policy_path),
        )
    )
    # engine -> recorder is exactly what RuntimeMonitor.process does;
    # we drive it directly only to hold the sealed record so executor
    # feedback can be anchored to its decision_id.
    prev: dict[str, str | None] = {}
    for i, (agent, capability, args, status) in enumerate(SCENARIO):
        action = AgentAction(
            agent_id=agent,
            capability=capability,
            timestamp=T0 + i * 7.0,
            arguments=args,
        )
        result = rt.engine.decide(action, prev.get(agent))
        record = rt.recorder.record(action, result)
        rt.recorder.report_outcome(record.decision_id, status)
        # behavioural state advances only on ALLOW, as the monitor does
        if result.decision.value == "allow":
            prev[agent] = capability
    path = rt.store.export_jsonl(out)
    rt.store.close()
    shutil.rmtree(tmp, ignore_errors=True)
    return path


def make_divergent(clean: Path, out: Path) -> bool:
    """Flip one execution event that reported 'refused' on a blocked
    decision to 'ok' -- the runtime said BLOCK, the world executed."""
    rows = [json.loads(line) for line in clean.read_text().splitlines() if line]
    blocked = {
        r["decision_id"]
        for r in rows
        if r.get("kind") == "decision" and r.get("decision") == "block"
    }
    for r in rows:
        if r.get("kind") == "execution" and r.get("decision_ref") in blocked:
            r["status"] = "ok"
            out.write_text(
                "\n".join(
                    json.dumps(x, sort_keys=True, separators=(",", ":")) for x in rows
                )
                + "\n"
            )
            return True
    return False


def make_tampered(clean: Path, out: Path) -> bool:
    """Edit a sealed decision's reason field after the fact."""
    rows = [json.loads(line) for line in clean.read_text().splitlines() if line]
    for r in rows:
        if r.get("kind") == "decision" and r.get("decision") == "block":
            r["reason"] = "approved by treasury desk"
            out.write_text(
                "\n".join(
                    json.dumps(x, sort_keys=True, separators=(",", ":")) for x in rows
                )
                + "\n"
            )
            return True
    return False


README = """# PrivateVault evidence bundle (DRP drp/0.1)

Three ledger files and the verifier that reads them. The verifier is
standard-library Python only and imports nothing from the runtime that
produced these records -- verification does not require trusting the
producer.

    python3 verify_records.py clean.jsonl        # expect: VERDICT: PASS
    python3 verify_records.py divergent.jsonl    # expect: FAIL
    python3 verify_records.py tampered.jsonl     # expect: FAIL

What each file is:

- **clean.jsonl** -- a real session emitted by the enforcement runtime:
  two agents, routine reads, a high-value transfer held for dual
  control, a forbidden bulk export, a blocked account drain, plus
  executor feedback anchored to each decision.
- **divergent.jsonl** -- the same ledger with one execution outcome
  changed to claim success on an action the runtime BLOCKED. This is
  the case that matters for a counterparty: the log proves the runtime
  refused and something executed anyway.
- **tampered.jsonl** -- the same ledger with one sealed decision's
  `reason` rewritten after the fact.

What verification proves, per file:

| Attack on the log                      | Detected by            |
|----------------------------------------|------------------------|
| Edit any field of any record           | record_hash mismatch   |
| Delete or reorder records              | per-agent chain break  |
| Forge an execution result              | anchor mismatch        |
| BLOCK recorded, action executed anyway | enforcement divergence |

Integrity of the bundle itself:

    sha256sum -c MANIFEST.sha256

Format, JSON Schemas, canonical test vectors and the verifier are
published independently of the product under Apache-2.0 / CC-BY-4.0:
https://github.com/LOLA0786/drp-spec

Known limits, stated plainly: drp/0.1 has one production
implementation and no external adopters yet, so portability is a
property of the format, not yet a demonstrated fact of the ecosystem.
The records carry integrity and lineage semantics only -- no severity
taxonomy, materiality or cross-emitter comparability.
"""


def main() -> int:
    ap = argparse.ArgumentParser(description="Build a counterparty evidence bundle.")
    ap.add_argument("-o", "--out", default="evidence-bundle")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    clean = build_ledger(out / "clean.jsonl")
    n = sum(1 for _ in clean.open())
    print(f"clean.jsonl: {n} records")

    if not make_divergent(clean, out / "divergent.jsonl"):
        print("ERROR: no blocked decision with an execution event")
        return 1
    if not make_tampered(clean, out / "tampered.jsonl"):
        print("ERROR: no blocked decision to tamper with")
        return 1

    shutil.copy(ROOT / "tools" / "verify_records.py", out / "verify_records.py")
    (out / "README.md").write_text(README)

    manifest = []
    for f in sorted(out.iterdir()):
        if f.name == "MANIFEST.sha256":
            continue
        h = hashlib.sha256(f.read_bytes()).hexdigest()
        manifest.append(f"{h}  {f.name}")
    (out / "MANIFEST.sha256").write_text("\n".join(manifest) + "\n")

    print(f"bundle written: {out.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
