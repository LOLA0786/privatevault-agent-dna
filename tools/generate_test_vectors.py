#!/usr/bin/env python3
"""
Generate canonical DRP test vectors into spec/test-vectors/.

Four files:
  1. clean.jsonl              — verifier must PASS
  2. tampered_field.jsonl     — a BLOCK flipped to ALLOW; must FAIL (hash mismatch)
  3. deleted_record.jsonl     — a refusal silently removed; must FAIL (chain break)
  4. divergent.jsonl          — BLOCK decision, ok execution; must FAIL (divergence)

Run from repo root: python3 tools/generate_test_vectors.py
"""

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent_dna.advisory import AdvisorySignal, Severity          # noqa: E402
from agent_dna.decision import Decision, DecisionEngine          # noqa: E402
from agent_dna.decision_recorder import DecisionRecorder         # noqa: E402
from agent_dna.decision_store import DecisionStore               # noqa: E402
from agent_dna.trace import AgentAction                          # noqa: E402

DEFAULT_OUT = Path(__file__).resolve().parent.parent / "spec" / "test-vectors"


class Scorer:
    def score(self, action, prev_capability=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.0,
            severity=Severity.INFO,
            reasons=[],
        )


class Invariants:
    def validate(self, capability, previous):
        class R:
            pass
        r = R()
        r.violated = capability == "payments.drain_account"
        r.message = (
            "invariant: payments.drain_account is forbidden"
            if r.violated else ""
        )
        return r


def build_stream(path, *, divergent=False):
    store = DecisionStore(path)
    recorder = DecisionRecorder(store=store)
    engine = DecisionEngine(scorer=Scorer(), invariants=Invariants())

    prev = None
    decisions = []
    for cap in (
        "crm.read_contact",
        "email.send",
        "payments.drain_account",   # BLOCK
        "crm.update_contact",
    ):
        a = AgentAction(
            agent_id="payment-agent-01",
            capability=cap,
            timestamp=time.time(),
        )
        r = engine.decide(a, prev)
        rec = recorder.record(a, r)
        decisions.append((rec, r))
        if r.decision == Decision.ALLOW:
            prev = cap

    for rec, r in decisions:
        if r.decision == Decision.BLOCK:
            status = "ok" if divergent else "refused"
        else:
            status = "ok"
        recorder.report_outcome(rec.decision_id, status)

    return path


def main(out: Path | None = None):
    """Write vectors into ``out`` (default: the canonical spec dir).

    Overwriting the canonical dir is a DELIBERATE act (protocol
    change); tests that only need current-serialization output must
    pass a temp dir instead — the committed vectors are pinned by
    tests/test_vector_immutability.py.
    """
    OUT = out or DEFAULT_OUT
    OUT.mkdir(parents=True, exist_ok=True)
    for f in OUT.glob("*.jsonl"):
        f.unlink()

    # 1. clean
    clean = build_stream(OUT / "clean.jsonl")

    # 2. tampered field — flip the BLOCK to allow
    lines = clean.read_text().splitlines()
    tampered = []
    for line in lines:
        d = json.loads(line)
        if d.get("kind") == "decision" and d.get("decision") == "block":
            d["decision"] = "allow"
        tampered.append(json.dumps(d, sort_keys=True, separators=(",", ":")))
    (OUT / "tampered_field.jsonl").write_text("\n".join(tampered) + "\n")

    # 3. deleted record — drop the BLOCK decision line
    kept = [
        line for line in lines
        if not (
            json.loads(line).get("kind") == "decision"
            and json.loads(line).get("decision") == "block"
        )
    ]
    (OUT / "deleted_record.jsonl").write_text("\n".join(kept) + "\n")

    # 4. divergence — regenerate with executor claiming the BLOCK ran
    build_stream(OUT / "divergent.jsonl", divergent=True)

    for f in sorted(OUT.glob("*.jsonl")):
        n = len(f.read_text().splitlines())
        print(f"wrote {f.name} ({n} records)")


if __name__ == "__main__":
    import argparse
    _ap = argparse.ArgumentParser()
    _ap.add_argument("--out", type=Path, default=None,
                     help="output dir (default: canonical spec/test-vectors)")
    _args = _ap.parse_args()
    main(_args.out)
