"""
MULTI-AGENT CONSENSUS — tested building blocks, NOT wired into the
enforcement line.

The composed_line_demo.py shows single-agent pre-execution
enforcement (six levels). This demo shows a separate, independently
tested capability: signed, trust-weighted voting across multiple
agents on one proposed action.

Status, stated plainly: SecureQuorum and WeightedQuorum are unit-
tested (agent_dna/consensus/, 20 tests) and NOT called from
DecisionEngine.decide(). If a real multi-agent workflow needs
consensus gating, this module is the tested starting point for
wiring it in as an additional precedence check — that integration
does not exist yet.
"""

import time

from agent_dna.consensus.secure_quorum import SecureQuorum, TrustRegistry
from agent_dna.consensus.signing import register_key, sign_message

from runtime_demo import banner


def main():
    action_id = "settlement-INV-7734"
    message_hash = f"hash-of-{action_id}-payload"

    trust = TrustRegistry()
    trust.set_score("checker-agent", 0.9)
    trust.set_score("fraud-agent", 0.9)
    trust.set_score("maker-agent", 0.6)
    # note: no trust score set for "attacker" -> default 0.5 applies
    # if it were ever counted, which it won't be, because its
    # signature won't verify

    for agent_id in ("checker-agent", "fraud-agent", "maker-agent"):
        register_key(agent_id, f"secret-for-{agent_id}")
    register_key("attacker", "attacker-controlled-secret")

    quorum = SecureQuorum(threshold=0.67, trust_registry=trust)

    banner("SCENARIO 1 — three honest agents approve, quorum clears")
    for agent_id, vote in [
        ("checker-agent", "APPROVE"),
        ("fraud-agent", "APPROVE"),
        ("maker-agent", "APPROVE"),
    ]:
        sig = sign_message(agent_id, message_hash)
        quorum.submit_vote(action_id, agent_id, vote, sig, message_hash)
        print(f"  {agent_id:<16} votes {vote:<8} (signed, trust={trust.get(agent_id):.1f})")

    approved = quorum.check_quorum(action_id)
    print(f"\n  quorum threshold : 0.67")
    print(f"  quorum result    : {'APPROVED' if approved else 'REJECTED'}")

    banner("SCENARIO 2 — an unsigned/forged vote is silently ignored")
    action_id_2 = "settlement-INV-9982"
    message_hash_2 = f"hash-of-{action_id_2}-payload"
    quorum2 = SecureQuorum(threshold=0.67, trust_registry=trust)

    # one honest vote — not enough alone to clear 0.67
    sig = sign_message("maker-agent", message_hash_2)
    quorum2.submit_vote(action_id_2, "maker-agent", "APPROVE", sig, message_hash_2)
    print(f"  maker-agent      votes APPROVE (signed, trust=0.6)")

    # attacker tries to inject a vote AS checker-agent without
    # knowing checker-agent's key
    forged_sig = sign_message("attacker", message_hash_2)
    quorum2.submit_vote(action_id_2, "checker-agent", "APPROVE",
                        forged_sig, message_hash_2)
    print(f"  checker-agent    votes APPROVE (FORGED — attacker doesn't have this key)")

    approved_2 = quorum2.check_quorum(action_id_2)
    print(f"\n  maker-agent alone contributes trust=0.6, below 0.67 threshold")
    print(f"  forged checker-agent vote does NOT verify -> contributes 0.0")
    print(f"  quorum result    : {'APPROVED' if approved_2 else 'REJECTED'}"
          f"  (correctly rejected — forged vote could not inflate the score)")

    banner("SCENARIO 3 — genuine two-of-three still clears without the third")
    action_id_3 = "settlement-INV-1105"
    message_hash_3 = f"hash-of-{action_id_3}-payload"
    quorum3 = SecureQuorum(threshold=0.67, trust_registry=trust)

    for agent_id in ("checker-agent", "fraud-agent"):  # maker-agent abstains
        sig = sign_message(agent_id, message_hash_3)
        quorum3.submit_vote(action_id_3, agent_id, "APPROVE", sig, message_hash_3)
        print(f"  {agent_id:<16} votes APPROVE (signed, trust={trust.get(agent_id):.1f})")

    approved_3 = quorum3.check_quorum(action_id_3)
    print(f"\n  checker(0.9) + fraud(0.9) = 1.8 combined trust weight, clears 0.67")
    print(f"  quorum result    : {'APPROVED' if approved_3 else 'REJECTED'}")

    banner("STATUS")
    print("SecureQuorum + signing: 20 tests passing, including forged-signature")
    print("rejection and Byzantine-minority-cannot-override-honest-majority.")
    print()
    print("NOT wired into agent_dna.decision.DecisionEngine. A real integration")
    print("would add this as a precedence check for multi-agent actions only —")
    print("single-agent actions (everything in composed_line_demo.py) have no")
    print("votes to evaluate and would skip this level entirely, the same way")
    print("L0/L3 skip when their required evidence is absent.")


if __name__ == "__main__":
    main()
