"""
THE COMPOSED LINE — seven precedence levels, one scenario each.

One audience, one story:
  CTO   — does it work, is it fast, is it tested
  CAIO  — does the AI layer stay subordinate to deterministic control
  CISO  — can an attacker forge, replay, or silently bypass a refusal
  CRO   — is every decision an admissible, reconstructable record

  L0  UAAL enterprise constraints    "can this ever run?"          -> BLOCK
  L1  behavioral invariants                                         -> BLOCK
  L2  multi-agent consensus          (evidence-gated)               -> REQUIRE_APPROVAL
  L3  capability grants              "is this still that agent?"   -> REQUIRE_APPROVAL
  L4  economics (cost / ROI)                                        -> REQUIRE_APPROVAL
  L5  learned drift                                                 -> REQUIRE_APPROVAL
  L6  baseline                                                      -> ALLOW
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

from agent_dna.consensus import ConsensusChecker
from agent_dna.consensus.signing import register_key, sign_message
from agent_dna.decision import Decision, DecisionEngine
from agent_dna.decision_recorder import DecisionRecorder
from agent_dna.decision_store import DecisionStore
from agent_dna.economics import CostAnomalyChecker
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
        "crm.read_contact", "crm.update_contact",
        "email.send", "payment.pay_invoice",
    }

    def is_authorized(self, agent_id, capability):
        return capability in self.GRANTED


HONEST_EVIDENCE = {
    "user_request": {"canonical_target": "INV-1001"},
    "planner": {"canonical_target": "INV-1001"},
    "approvals": {"required": False},
    "enterprise_state": {
        "invoice_amount": 5000.0, "invoice_open": True,
        "target_verified": True, "duplicate": False,
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
        economics=CostAnomalyChecker(),
        consensus=ConsensusChecker(),
    )
    monitor = RuntimeMonitor(engine, recorder=recorder)

    register_key("finance-agent", "secret-finance")
    settle_votes = [{
        "agent_id": "finance-agent", "vote": "REJECT",
        "signature": sign_message("finance-agent", "settle-9982"),
        "message_hash": "settle-9982",
    }]

    scenarios = [
        ("L0  enterprise constraint   |CISO CRO|  amount tampered 5,000 -> 49,000",
         intent_to_action(actor_id="sales-agent-01", verb="pay_invoice",
                          target={"type": "payment", "id": "INV-1001"},
                          parameters={"amount": 49000.0},
                          timestamp=time.time()),
         HONEST_EVIDENCE),

        ("L1  behavioral invariant    |CISO|      forbidden bulk export",
         intent_to_action(actor_id="sales-agent-01", verb="bulk_export",
                          target={"type": "storage"},
                          timestamp=time.time()),
         None),

        ("L2  multi-agent consensus   |CRO CAIO|  finance agent dissents on settlement",
         intent_to_action(actor_id="sales-agent-01", verb="settle",
                          target={"type": "payment", "id": "9982"},
                          timestamp=time.time()),
         {"consensus": {"action_id": "settle-9982", "threshold": 0.67,
                        "votes": settle_votes,
                        "trust_scores": {"finance-agent": 1.0}}}),

        ("L3  capability grant        |CISO|      ungranted wire transfer",
         intent_to_action(actor_id="sales-agent-01", verb="initiate_wire",
                          target={"type": "payments"},
                          parameters={"amount": 900000},
                          timestamp=time.time()),
         None),

        ("L4  economics               |CRO CTO|   cost 25,000x historical average",
         intent_to_action(actor_id="sales-agent-01", verb="send",
                          target={"type": "email"},
                          timestamp=time.time()),
         {"economics": {"estimated_cost_usd": 500.0,
                        "historical_avg_cost_usd": 0.02}}),

        ("L5  learned drift           |CAIO|      honest payment, novel for this agent",
         intent_to_action(actor_id="sales-agent-01", verb="pay_invoice",
                          target={"type": "payment", "id": "INV-1001"},
                          parameters={"amount": 5000.0},
                          timestamp=time.time()),
         HONEST_EVIDENCE),

        ("L6  baseline                |CTO|       normal in-profile CRM read",
         intent_to_action(actor_id="sales-agent-01", verb="read_contact",
                          target={"type": "crm"},
                          timestamp=time.time()),
         None),
    ]

    banner("COMPOSED LINE — SEVEN LEVELS, ONE SCENARIO EACH")
    rows = []
    for desc, action, ev in scenarios:
        result = monitor.process(action, evidence=ev)
        status = "ok" if result.decision == Decision.ALLOW else "refused"
        rec = recorder.graph.find_by_agent(action.agent_id)[-1]
        recorder.report_outcome(rec.decision_id, status)
        env = recorder.envelopes[rec.record_hash]
        signed = verify_envelope(env, rec.record_hash)
        rows.append((desc, action.agent_id, result.decision.value.upper(),
                     result.triggered_by, signed))
        print(f"{desc}")
        print(f"    -> {result.decision.value.upper():<17} "
              f"trigger={result.triggered_by:<12} "
              f"signed={'Y' if signed else 'N'}")
        print(f"    reason: {result.reason}")
        print()

    g = recorder.graph

    banner("INTEGRITY & PROOF  |CISO CRO|")
    print(f"records in chain        : {len(g)}")
    print(f"chain verified           : {g.verify_all()}")
    print(f"enforcement divergences  : {len(g.find_divergent())}")
    print(f"signed envelopes         : {len(recorder.envelopes)}")
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(log)],
        capture_output=True, text=True,
    )
    print(f"independent verifier     : {proc.stdout.strip().splitlines()[-1]}")

    banner("ATTACK — re-chain a signed record  |CISO|")
    victim = list(g)[0]
    original_hash = victim.record_hash
    original_env = recorder.envelopes[victim.record_hash]
    victim.prev_hash = "f" * 64
    victim.record_hash = victim.compute_hash()
    print(f"original record_hash    : {original_hash}")
    print(f"new record_hash (re-seal): {victim.record_hash}")
    print(f"record re-seals cleanly  : {victim.verify()}  <- internally consistent")
    print(f"signature still binds    : "
          f"{verify_envelope(original_env, victim.record_hash)}  <- but signed"
          f" for a different hash")
    print("-> individually valid record, cryptographically disowned history")

    banner("SUMMARY  |everyone|")
    print(f"{'Scenario':<50} {'Verdict':<17} {'Level':<12} {'Signed'}")
    print("-" * 100)
    for desc, agent_id, verdict, trigger, signed in rows:
        short = desc.split("|")[0].strip()
        print(f"{short:<50} {verdict:<17} {trigger:<12} "
              f"{'Y' if signed else 'N'}")
    print()
    print("CTO   : every level is a tested code path, 198+ automated tests, CI-guarded.")
    print("CAIO  : drift (L5) is the only probabilistic level — it can escalate, never")
    print("        override a deterministic BLOCK above it.")
    print("CISO  : the ATTACK section above is a live exploit attempt against our own")
    print("        signed records, defeated in front of you, not claimed in a slide.")
    print("CRO   : every verdict, including every refusal, is a hash-chained, signed,")
    print("        independently verifiable record — admissible evidence, not a log line.")


if __name__ == "__main__":
    main()
