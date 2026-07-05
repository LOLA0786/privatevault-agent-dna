"""
THE PERFECT LINE — one ActionRequest through all three layers.

  L0  UAAL enterprise constraints    "can this ever run?"
  L1  behavioral invariants
  L2  capability grants              "is this still that agent?"
  L3  learned drift
  L4  baseline
       |
  sealed DecisionRecord -> Ed25519 envelope   "prove it later"
       |
  DecisionGraph -> store -> ExecutionEvent -> independent verifier
"""

import subprocess
import sys
import tempfile
import time
from pathlib import Path

from agent_dna.decision import Decision, DecisionEngine
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.decision_store import DecisionStore
from agent_dna.intent_adapter import intent_to_action
from agent_dna.runtime import RuntimeMonitor
from agent_dna.signer import ReceiptSigner, generate_keypair, verify_envelope
from agent_dna.uaal_layer import UAALConstraintChecker

from runtime_demo import banner, train

ROOT = Path(__file__).resolve().parent.parent
VERIFIER = ROOT / "tools" / "verify_records.py"


class Invariants:
    def validate(self, capability, previous):
        class R:
            pass
        r = R()
        r.violated = capability == "storage.bulk_export"
        r.message = "invariant: bulk export forbidden" if r.violated else ""
        return r


class Authorizer:
    GRANTED = {
        "crm.read_contact",
        "crm.update_contact",
        "email.send",
        "payment.pay_invoice",
    }

    def is_authorized(self, agent_id, capability):
        return capability in self.GRANTED


EVIDENCE = {
    "user_request": {"canonical_target": "INV-1001"},
    "planner": {"canonical_target": "INV-1001"},
    "approvals": {"required": False},
    "enterprise_state": {
        "invoice_amount": 5000.0,
        "invoice_open": True,
        "target_verified": True,
        "duplicate": False,
    },
}


def main():
    workdir = Path(tempfile.mkdtemp(prefix="pv_line_"))
    log = workdir / "decisions.jsonl"
    keys = generate_keypair()

    recorder = DecisionRecorder(
        store=DecisionStore(log),
        signer=ReceiptSigner(seed_hex=keys["signing_key"]),
    )
    engine = DecisionEngine(
        scorer=train(),
        invariants=Invariants(),
        authorizer=Authorizer(),
        uaal=UAALConstraintChecker(),
    )
    monitor = RuntimeMonitor(engine, recorder=recorder)

    banner("ONE STREAM, FIVE PRECEDENCE LEVELS")
    scenarios = [
        ("honest invoice payment",
         intent_to_action(actor_id="sales-agent-01", verb="pay_invoice",
                          target={"type": "payment", "id": "INV-1001"},
                          parameters={"amount": 5000.0},
                          timestamp=time.time()), EVIDENCE),
        ("AMOUNT TAMPERED 5000 -> 49000",
         intent_to_action(actor_id="sales-agent-01", verb="pay_invoice",
                          target={"type": "payment", "id": "INV-1001"},
                          parameters={"amount": 49000.0},
                          timestamp=time.time()), EVIDENCE),
        ("forbidden bulk export",
         intent_to_action(actor_id="sales-agent-01", verb="bulk_export",
                          target={"type": "storage"},
                          timestamp=time.time()), None),
        ("ungranted wire transfer",
         intent_to_action(actor_id="sales-agent-01", verb="initiate_wire",
                          target={"type": "payments"},
                          parameters={"amount": 900000},
                          timestamp=time.time()), None),
        ("in-profile CRM read",
         intent_to_action(actor_id="sales-agent-01", verb="read_contact",
                          target={"type": "crm"},
                          timestamp=time.time()), None),
    ]

    for desc, action, ev in scenarios:
        result = monitor.process(action, evidence=ev)
        status = "ok" if result.decision == Decision.ALLOW else "refused"
        rec = recorder.graph.find_by_agent(action.agent_id)[-1]
        recorder.report_outcome(rec.decision_id, status)
        env = recorder.envelopes[rec.record_hash]
        signed = verify_envelope(env, rec.record_hash)
        print(
            f"{desc:<34} {result.decision.value.upper():<17}"
            f" L={result.triggered_by:<16} signed={'Y' if signed else 'N'}"
        )

    g = recorder.graph
    banner("LAYER ATTRIBUTION")
    for r in g:
        print(f"{r.capability:<26} {r.decision:<17} triggered_by={r.triggered_by}")

    banner("PROOF")
    print(f"chains verified   : {g.verify_all()}")
    print(f"divergent         : {len(g.find_divergent())}")
    print(f"signed envelopes  : {len(recorder.envelopes)}")
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(log)],
        capture_output=True, text=True,
    )
    print(proc.stdout.splitlines()[-1])

    banner("ATTACK: re-chain a signed record")
    victim = list(g)[1]
    original_env = recorder.envelopes[victim.record_hash]
    victim.prev_hash = "f" * 64
    victim.record_hash = victim.compute_hash()
    print(f"record re-seals cleanly : {victim.verify()}")
    print(f"signature still binds   : "
          f"{verify_envelope(original_env, victim.record_hash)}")
    print("-> individually valid record, cryptographically disowned history")


if __name__ == "__main__":
    main()
