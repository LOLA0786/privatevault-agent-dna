"""PrivateVault CABI -- enterprise demo: high-value payment authorization swarm.

Models a regulated bank's autonomous payment-authorization pipeline as an agent
society and shows the Cross-Agent Behavioral Invariant engine enforcing the
controls a CRO / CISO actually answers to:

  sanctioned flow:
    intake -> kyc -> sanctions -> limit -> fraud -> maker -> checker -> settlement

  collective sign-off required before settlement (four-eyes + automated gates):
    sanctions, fraud, maker, checker  must all clear BEFORE settlement fires.

The point a per-agent monitor misses: in several of these attacks every
individual agent is behaving normally. Only the *collective* decision is
illegitimate -- a skipped sanctions screen, a maker-checker that collapsed to
one approver, a settlement that fired before the fraud hold cleared.

Run:  python -m examples.bfsi_payment_swarm_demo
"""
from __future__ import annotations

from agent_dna.multi_agent import InteractionEvent, RuntimeValidator, Verdict

ROLE = {
    "intake_agent": "intake",
    "kyc_agent": "kyc",
    "sanctions_agent": "sanctions",
    "limit_agent": "limit",
    "fraud_agent": "fraud",
    "maker_agent": "maker",
    "checker_agent": "checker",
    "settlement_agent": "settlement",
}

# the sanctioned hand-off chain UP TO (but not including) settlement
PRE_SETTLEMENT = [
    ("intake_agent", "kyc_agent"),
    ("kyc_agent", "sanctions_agent"),
    ("sanctions_agent", "limit_agent"),
    ("limit_agent", "fraud_agent"),
    ("fraud_agent", "maker_agent"),
    ("maker_agent", "checker_agent"),
]

SIGNOFF_ROLES = ["sanctions", "fraud", "maker", "checker"]
SIGNOFF_AGENT = {
    "sanctions": "sanctions_agent", "fraud": "fraud_agent",
    "maker": "maker_agent", "checker": "checker_agent",
}


def step(exec_id, src, dst, t, **kw):
    return InteractionEvent(
        execution_id=exec_id, source=src, target=dst,
        source_role=ROLE.get(src, "unknown"), target_role=ROLE.get(dst, "unknown"),
        timestamp=t, intent="authorize_payment", **kw)


def clearance(exec_id, role, t, approve=True, confidence=0.97):
    return InteractionEvent(
        execution_id=exec_id, source=SIGNOFF_AGENT[role], target="consensus_ledger",
        source_role=role, target_role="ledger", timestamp=t,
        approval=approve, confidence=confidence, intent="post_clearance",
        metadata={"is_signoff": True})


def good_payment(exec_id, *, skip_clearance=None, dissent=None,
                early_settlement=False, extra=None):
    """A sanctioned high-value payment. Clearances are posted BEFORE the
    settlement hand-off, which is always the final act."""
    ev = []
    t = 1.0
    for src, dst in PRE_SETTLEMENT:
        ev.append(step(exec_id, src, dst, t))
        t += 1.0
    # t == 7.0 here

    if early_settlement:
        # settlement fires up front, before any clearance is posted
        ev.append(step(exec_id, "checker_agent", "settlement_agent", 1.5))

    # clearances posted to the ledger, just before settlement
    ct = t  # 7.0
    for role in SIGNOFF_ROLES:
        if skip_clearance and role == skip_clearance:
            ct += 0.1
            continue
        approve = not (dissent and role == dissent)
        ev.append(clearance(exec_id, role, ct, approve=approve))
        ct += 0.1

    if extra:
        ev.extend(extra(exec_id, ct))
        ct += 0.1

    if not early_settlement:
        ev.append(step(exec_id, "checker_agent", "settlement_agent", ct + 0.5))
    return ev


def build_corpus(n=500):
    corpus = []
    for i in range(n):
        corpus.extend(good_payment(f"prod-{i}"))
    return corpus


# ---- named enterprise attacks --------------------------------------------
def attack_sanctions_bypass(exec_id):
    # prompt-injected intake routes around AML/sanctions screening entirely
    ev = [
        step(exec_id, "intake_agent", "kyc_agent", 1.0),
        step(exec_id, "kyc_agent", "limit_agent", 2.0),       # bypass edge
        step(exec_id, "limit_agent", "fraud_agent", 3.0),
        step(exec_id, "fraud_agent", "maker_agent", 4.0),
        step(exec_id, "maker_agent", "checker_agent", 5.0),
    ]
    ct = 6.0
    for role in ["fraud", "maker", "checker"]:   # sanctions never clears
        ev.append(clearance(exec_id, role, ct))
        ct += 0.1
    ev.append(step(exec_id, "checker_agent", "settlement_agent", ct + 0.5))
    return ev


def attack_maker_checker_collapse(exec_id):
    return good_payment(exec_id, skip_clearance="checker")


def attack_privilege_escalation(exec_id):
    ev = good_payment(exec_id)
    ev.append(InteractionEvent(
        execution_id=exec_id, source="support_bot", target="settlement_agent",
        source_role="support", target_role="settlement", timestamp=99.0,
        intent="release_funds"))
    return ev


def attack_settle_before_screen(exec_id):
    return good_payment(exec_id, early_settlement=True)


def attack_fraud_override(exec_id):
    return good_payment(exec_id, dissent="fraud")


def benign_new_audit_agent(exec_id):
    def extra(eid, t):
        return [InteractionEvent(
            execution_id=eid, source="fraud_agent", target="audit_stream",
            source_role="fraud", target_role="unknown", timestamp=t,
            intent="emit_audit")]
    return good_payment(exec_id, extra=extra)


REG_NOTE = {
    "AML / sanctions screening skipped": "PMLA 2002 / RBI KYC Master Direction -- "
        "screening against UN/OFAC/RBI lists is mandatory before disbursement.",
    "maker-checker collapsed to a single approver": "RBI dual-control / four-eyes "
        "principle -- high-value payments require two independent approvers.",
    "unsanctioned agent triggered settlement": "Segregation of duties -- only the "
        "checker function may release funds.",
    "settlement fired before required clearances": "Control circumvention -- "
        "execution must follow, never precede, the control gates.",
    "fraud hold was overridden": "An open fraud hold (negative attestation) must "
        "block disbursement, not be silently bypassed.",
    "new unclassified agent observed a control": "Novel-but-unsanctioned wiring -- "
        "flagged for review, not blocked, pending onboarding.",
}


def run():
    validator = RuntimeValidator.from_corpus(build_corpus())

    import json
    print("LEARNED ORGANIZATIONAL DNA (from 500 clean production authorizations)")
    print(json.dumps(validator.engine.describe(), indent=2))
    print("=" * 72)

    cases = [
        ("Legitimate high-value payment", good_payment("live-ok"),
        Verdict.ALLOW, None),
        ("Prompt-injection: AML/sanctions bypass", attack_sanctions_bypass("a1"),
        Verdict.BLOCK, "AML / sanctions screening skipped"),
        ("Maker-checker collapse (four-eyes bypass)",
        attack_maker_checker_collapse("a2"),
        Verdict.BLOCK, "maker-checker collapsed to a single approver"),
        ("Privilege escalation: support bot releases funds",
        attack_privilege_escalation("a3"),
        Verdict.BLOCK, "unsanctioned agent triggered settlement"),
        ("Sequence tamper: settle before screening",
        attack_settle_before_screen("a4"),
        Verdict.BLOCK, "settlement fired before required clearances"),
        ("Fraud-hold override", attack_fraud_override("a5"),
        Verdict.BLOCK, "fraud hold was overridden"),
        ("Benign novelty: new audit agent", benign_new_audit_agent("a6"),
        Verdict.REVIEW, "new unclassified agent observed a control"),
    ]

    all_ok = True
    for label, events, want, note in cases:
        v = validator.validate_events(events)
        ok = v.verdict is want
        all_ok &= ok
        flag = "OK" if ok else "!! UNEXPECTED"
        print(f"\n### {label}")
        print(f"    VERDICT: {v.verdict.value}   [{flag}]")
        if note:
            print(f"    Regulatory exposure: {REG_NOTE[note]}")
        for r in v.results:
            if not r.passed:
                tag = "HARD" if r.hard else "soft"
                for vio in r.violations:
                    print(f"      [{tag}] {r.name}: {vio}")
    print("\n" + "=" * 72)
    print("DEMO RESULT:", "ALL VERDICTS AS EXPECTED" if all_ok else "MISMATCH")
    return all_ok


if __name__ == "__main__":
    raise SystemExit(0 if run() else 1)
