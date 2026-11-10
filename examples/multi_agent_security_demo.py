"""
Multi-Agent Security Layer -- four failures at the handoff between agents,
each attempted and each refused.

    python examples/multi_agent_security_demo.py

Exits non-zero if any attack succeeds.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from agent_dna.checkpoint import build_checkpoint  # noqa: E402
from agent_dna.consensus import ConsensusChecker, ConsensusConfig  # noqa: E402
from agent_dna.consensus.signing import (  # noqa: E402
    cast_vote_v2,
    consensus_action_id,
    generate_voter_keypair,
)
from agent_dna.multi_agent_security import (  # noqa: E402
    CounterpartyLedger,
    SqliteNonceLedger,
    TrustAnchors,
    authorize,
    issue_link,
)
from agent_dna.signer import ReceiptSigner, generate_keypair  # noqa: E402

FAILURES: list[str] = []


def expect(label: str, got: bool, want: bool, detail: str = "") -> None:
    mark = "ok  " if got == want else "FAIL"
    if got != want:
        FAILURES.append(label)
    print(f"  [{mark}] {label}: {'allowed' if got else 'refused'}")
    if detail:
        print(f"         {detail[:110]}")


def scene_delegation() -> None:
    print("\n1. AUTHORITY LAUNDERING -- delegation can only shrink")
    keys = {n: generate_voter_keypair() for n in ("operator", "planner", "payer")}
    anchors = TrustAnchors(
        roots={"operator": keys["operator"]["public_key"]},
        agents={n: keys[n]["public_key"] for n in ("planner", "payer")},
    )
    root = issue_link(
        keys["operator"]["signing_key"],
        delegator="operator",
        delegate="planner",
        capabilities=["payments.pay_invoice"],
        max_amount=500.0,
        may_delegate=True,
    )
    honest = issue_link(
        keys["planner"]["signing_key"],
        delegator="planner",
        delegate="payer",
        capabilities=["payments.pay_invoice"],
        max_amount=200.0,
        parent=root,
    )
    greedy = issue_link(
        keys["planner"]["signing_key"],
        delegator="planner",
        delegate="payer",
        capabilities=["payments."],
        max_amount=50_000.0,
        parent=root,
    )

    def ask(chain, capability, amount):
        return authorize(
            chain, anchors, agent_id="payer", capability=capability, amount=amount
        )

    d = ask([root, honest], "payments.pay_invoice", 150)
    expect("payer pays 150 under a 200 ceiling", d.allowed, True)
    d = ask([root, honest], "payments.pay_invoice", 450)
    expect("payer pays 450 (planner held 500, gave 200)", d.allowed, False, d.reason)
    d = ask([root, greedy], "payments.refund", 40_000)
    expect("planner hands on more than it was given", d.allowed, False, d.reason)


def scene_quorum(tmp: Path) -> None:
    print("\n2. FAKE AGREEMENT -- clones do not make a quorum")
    keys = {n: generate_voter_keypair() for n in ("risk-1", "risk-2", "auditor")}
    profile = {
        "risk-1": {"provider": "acme", "operator": "bank"},
        "risk-2": {"provider": "acme", "operator": "bank"},
        "auditor": {"provider": "globex", "operator": "outside-firm"},
    }
    config = ConsensusConfig.from_dict(
        {
            "threshold": 2.0,
            "require_distinct": {"provider": 2},
            "voters": [
                {
                    "agent_id": n,
                    "weight": 1.0,
                    "public_key": k["public_key"],
                    **profile[n],
                }
                for n, k in keys.items()
            ],
        }
    )
    agent, capability, arguments = "pay-agent", "payments.wire", {"amount": 9_000_000}
    action_id = consensus_action_id(agent, capability, arguments)

    def votes(*names):
        return {
            "consensus": {
                "action_id": action_id,
                "votes": [
                    cast_vote_v2(
                        keys[n]["signing_key"],
                        agent_id=n,
                        action_id=action_id,
                        vote="APPROVE",
                    )
                    for n in names
                ],
            }
        }

    def check(checker, evidence):
        return checker.check(
            evidence, agent_id=agent, capability=capability, arguments=arguments
        )

    ledger_path = tmp / "votes.db"
    replica_1 = ConsensusChecker(config, ledger=SqliteNonceLedger(ledger_path))
    replica_2 = ConsensusChecker(config, ledger=SqliteNonceLedger(ledger_path))

    r = check(replica_1, votes("risk-1", "risk-2"))
    expect("two agents on one provider approve", not r.flagged, False, r.reason)
    mixed = votes("risk-1", "auditor")
    r = check(replica_1, mixed)
    expect("two agents on different providers approve", not r.flagged, True)

    print("\n3. REPLAY -- a cleared quorum is spent on every replica")
    r = check(replica_2, mixed)
    expect("same votes replayed to a second replica", not r.flagged, False, r.reason)


def scene_counterparty(tmp: Path) -> None:
    print("\n4. DENIABILITY -- the other party holds your checkpoint")
    seller = generate_keypair()
    seller_signer = ReceiptSigner(seed_hex=seller["signing_key"])
    records = [
        f'{{"record_hash":"{i:064x}","kind":"decision","agent_id":"s"}}'
        for i in range(1, 6)
    ]
    ledger = CounterpartyLedger(tmp / "seller.jsonl", [seller["public_key"]])
    ledger.accept(build_checkpoint(records, signer=seller_signer))

    expect("seller's full history audits clean", ledger.audit(records) == [], True)
    failures = ledger.audit(records[:3])
    expect(
        "seller drops two disclosed records",
        failures == [],
        False,
        failures[0] if failures else "",
    )


def main() -> int:
    print("MULTI-AGENT SECURITY LAYER -- owner: Chandan Galani")
    with tempfile.TemporaryDirectory(prefix="pv_mas_") as tmp:
        scene_delegation()
        scene_quorum(Path(tmp))
        scene_counterparty(Path(tmp))
    print()
    if FAILURES:
        print(f"RESULT: {len(FAILURES)} scenario(s) went the wrong way: {FAILURES}")
        return 1
    print("RESULT: 8 of 8 scenarios went the right way")
    return 0


if __name__ == "__main__":
    sys.exit(main())
