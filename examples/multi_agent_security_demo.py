"""
Multi-Agent Security Layer -- four failures at the handoff between agents,
each attempted and each refused.

    python examples/multi_agent_security_demo.py

Exits non-zero if any attack succeeds.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from agent_dna.advisory import AdvisorySignal, Severity  # noqa: E402
from agent_dna.checkpoint import build_checkpoint  # noqa: E402
from agent_dna.consensus import ConsensusChecker, ConsensusConfig  # noqa: E402
from agent_dna.consensus.signing import (  # noqa: E402
    cast_vote_v2,
    consensus_action_id,
    generate_voter_keypair,
)
from agent_dna.decision import DecisionEngine  # noqa: E402
from agent_dna.decision_recorder import DecisionRecorder  # noqa: E402
from agent_dna.multi_agent_security import (  # noqa: E402
    CounterpartyLedger,
    DelegationChallenges,
    DelegationGate,
    DelegationPolicy,
    SqliteNonceLedger,
    TrustAnchors,
    authorize,
    delegated_action_id,
    issue_link,
    link_hash,
    sign_possession,
    sign_presentation,
)
from agent_dna.open_authorizer import OpenAuthorizer  # noqa: E402
from agent_dna.signer import ReceiptSigner, generate_keypair  # noqa: E402
from agent_dna.sqlite_store import SQLiteDecisionStore  # noqa: E402
from agent_dna.trace import AgentAction  # noqa: E402

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

    receiver = DelegationChallenges("demo-payments-receiver")

    def proof_for(chain, capability, amount):
        # Receiver owns these exact bytes. No network payment is sent.
        request_bytes = json.dumps(
            {"capability": capability, "amount": amount}
        ).encode()
        digest = hashlib.sha256(request_bytes).hexdigest()
        challenge = receiver.issue(
            chain_hash=link_hash(chain[-1]),
            agent_id="payer",
            capability=capability,
            amount=amount,
            request_hash=digest,
        )
        return {
            "agent_id": "payer",
            "capability": capability,
            "amount": amount,
            "request_hash": digest,
            "challenges": receiver,
            "proof": sign_possession(keys["payer"]["signing_key"], challenge),
        }

    def ask(chain, capability, amount):
        return authorize(chain, anchors, **proof_for(chain, capability, amount))

    params = proof_for([root, honest], "payments.pay_invoice", 150)
    d = authorize([root, honest], anchors, **params)
    expect("payer pays 150 under a 200 ceiling", d.allowed, True)
    d = authorize([root, honest], anchors, **params)
    expect("same signed request presented again", d.allowed, False, d.reason)
    d = authorize(
        [root, honest],
        anchors,
        agent_id="payer",
        capability="payments.pay_invoice",
        amount=150,
    )
    expect("copied chain with no payer signature", d.allowed, False, d.reason)
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


class _DemoScorer:
    def score(self, action, prev=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.0,
            severity=Severity.INFO,
            reasons=[],
        )


def scene_counterparty(tmp: Path) -> None:
    print("\n4. DENIABILITY -- the other party holds your checkpoint")
    seller = generate_keypair()
    seller_signer = ReceiptSigner(seed_hex=seller["signing_key"])
    # Real DRP records, generated locally with a demo-only open authorizer.
    store = SQLiteDecisionStore(tmp / "demo-records.db")
    engine = DecisionEngine(scorer=_DemoScorer(), authorizer=OpenAuthorizer())
    recorder = DecisionRecorder(store=store, signer=seller_signer)
    try:
        for _ in range(5):
            action = AgentAction(
                agent_id="seller", capability="ledger.read", timestamp=time.time()
            )
            recorder.record(action, engine.decide(action))
        export_path = Path(store.export_jsonl(tmp / "records.jsonl"))
        records = export_path.read_text().splitlines()
    finally:
        store.close()
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
    edited = json.loads(records[0])
    edited["capability"] = "payments.wire_everything"
    tampered = [json.dumps(edited), *records[1:]]
    failures = ledger.audit(tampered)
    expect(
        "seller edits contents but keeps the original hash",
        failures == [],
        False,
        failures[0] if failures else "",
    )


def scene_live_gate() -> None:
    print("\n5. ON THE DECISION PATH -- the runtime checks the chain on every call")
    keys = {
        n: generate_voter_keypair() for n in ("operator", "planner", "payer", "thief")
    }
    policy = DelegationPolicy.from_dict(
        {
            "audience": "pv-demo",
            "roots": {"operator": keys["operator"]["public_key"]},
            "agents": {n: keys[n]["public_key"] for n in ("planner", "payer")},
            "required_agents": ["payer"],
        }
    )
    engine = DecisionEngine(
        scorer=_QuietScorer(),
        authorizer=OpenAuthorizer(),
        delegation=DelegationGate(policy),
    )
    root = issue_link(
        keys["operator"]["signing_key"],
        delegator="operator",
        delegate="planner",
        capabilities=["payments."],
        max_amount=500.0,
        may_delegate=True,
    )
    leaf = issue_link(
        keys["planner"]["signing_key"],
        delegator="planner",
        delegate="payer",
        capabilities=["payments.pay_invoice"],
        max_amount=200.0,
        parent=root,
    )
    arguments = {"amount": 150, "payee_id": "V-100"}

    def decide(signer: str | None):
        evidence = None
        if signer is not None:
            evidence = {
                "delegation": {
                    "chain": [root, leaf],
                    "presentation": sign_presentation(
                        keys[signer]["signing_key"],
                        audience="pv-demo",
                        chain_hash=link_hash(leaf),
                        action_id=delegated_action_id(
                            "payer", "payments.pay_invoice", arguments
                        ),
                    ),
                }
            }
        action = AgentAction(
            agent_id="payer",
            capability="payments.pay_invoice",
            timestamp=time.time(),
            arguments=dict(arguments),
        )
        return engine.decide(action, evidence=evidence)

    r = decide(None)
    expect(
        "sub-agent acts on its standing grant, no chain",
        r.decision.value == "allow",
        False,
        r.reason,
    )
    r = decide("thief")
    expect(
        "copied chain, presented without the holder's key",
        r.decision.value == "allow",
        False,
        r.reason,
    )
    r = decide("payer")
    expect("chain presented by its holder", r.decision.value == "allow", True, r.reason)


class _QuietScorer:
    def score(self, action, prev=None):
        return AdvisorySignal(
            agent_id=action.agent_id,
            capability=action.capability,
            drift_score=0.0,
            severity=Severity.INFO,
            reasons=[],
        )


def main() -> int:
    print("MULTI-AGENT SECURITY LAYER -- owner: Chandan Galani")
    with tempfile.TemporaryDirectory(prefix="pv_mas_") as tmp:
        scene_delegation()
        scene_quorum(Path(tmp))
        scene_counterparty(Path(tmp))
        scene_live_gate()
    print()
    if FAILURES:
        print(f"RESULT: {len(FAILURES)} scenario(s) went the wrong way: {FAILURES}")
        return 1
    print("RESULT: 14 of 14 scenarios went the right way")
    return 0


if __name__ == "__main__":
    sys.exit(main())
