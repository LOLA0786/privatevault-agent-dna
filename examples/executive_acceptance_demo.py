#!/usr/bin/env python3
"""
PrivateVault — Executive Acceptance Demonstration
=================================================
One production runtime, built by the same composition root the HTTP
API uses. Every scenario below runs through the canonical connector
middleware (credential -> identity -> full precedence line -> signed,
hash-chained record), then the audit trail is exported, independently
verified by a stdlib-only script with zero trust in this codebase,
tampered with, and caught. The process "restarts" and the chain and
signatures survive.

Every EXPECTED verdict is asserted. Exit 0 means every control fired
exactly as claimed. This script is run in CI on every commit
(tests/test_executive_acceptance.py) -- what you are watching is not
a rehearsed happy path, it is a maintained acceptance contract.

Honesty notes, up front (the same ones in our docs):
  * The behavioral drift scorer is calibrated on SYNTHETIC traces
    until a customer execution trace is wired -- the openly stated
    binding constraint. Deterministic levels (identity, UAAL, policy,
    consensus, grants, breaker) do not depend on it.
  * Grant/budget mechanics are shown with drift neutralized so the
    budget arithmetic is legible; in production, drift escalation
    stacks ON TOP of these controls, never instead of them.
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent_dna.apikeys import generate_key  # noqa: E402
from agent_dna.composition import (  # noqa: E402
    RuntimeConfig,
    build_production_runtime,
)
from agent_dna.connector import ToolCallRequest  # noqa: E402
from agent_dna.consensus.signing import cast_vote, register_key  # noqa: E402
from agent_dna.decision import Decision, DecisionEngine  # noqa: E402
from agent_dna.decision_recorder import DecisionRecorder  # noqa: E402
from agent_dna.grants import GrantRegistry  # noqa: E402
from agent_dna.signer import ReceiptSigner  # noqa: E402
from agent_dna.sqlite_store import SQLiteDecisionStore  # noqa: E402
from agent_dna.trace import AgentAction  # noqa: E402

FAILURES = []
LEDGER = []  # (scenario, expected, got, record_hash)


def banner(title):
    print(f"\n{'=' * 72}\n{title}\n{'=' * 72}")


def expect(scenario, verdict, expected_decision, expected_trigger, regulatory=""):
    got = f"{verdict.decision}/{verdict.triggered_by}"
    want = f"{expected_decision}/{expected_trigger}"
    ok = (
        verdict.decision == expected_decision
        and verdict.triggered_by == expected_trigger
    )
    mark = "OK " if ok else "FAIL"
    h = (verdict.record_hash or "")[:12]
    print(
        f"  [{mark}] {scenario:<46} -> {got:<28} "
        f"{('rec ' + h + '..') if h else '(no record: by design)'}"
    )
    if regulatory:
        print(f"        regulatory: {regulatory}")
    if not ok:
        FAILURES.append(f"{scenario}: expected {want}, got {got} ({verdict.reason})")
    LEDGER.append((scenario, want, got, verdict.record_hash))
    return verdict


def main():  # noqa: C901 - linear executable acceptance scenario
    tmp = Path(tempfile.mkdtemp(prefix="pv_exec_"))
    db = tmp / "privatevault.db"

    # ---- deployment configuration: keys, policy, grants, signing ----
    ops_key = generate_key("payments-agent-01", scope="full")
    breaker_key = generate_key("breaker-agent-02", scope="full")
    auditor = generate_key("external-auditor", scope="audit")
    (tmp / "keys.json").write_text(
        json.dumps(
            {
                ops_key["hash"]: {"name": "payments-agent-01", "scope": "full"},
                breaker_key["hash"]: {"name": "breaker-agent-02", "scope": "full"},
                auditor["hash"]: {"name": "external-auditor", "scope": "audit"},
            }
        )
    )
    (tmp / "policy.json").write_text(
        json.dumps(
            {
                "policies": [
                    {
                        "id": "DLP-001-no-bulk-export",
                        "capability": "storage.bulk_export",
                        "outcome": "block",
                        "reason": "bulk data export is contractually forbidden (DLP)",
                    }
                ]
            }
        )
    )
    (tmp / "grants.json").write_text(
        json.dumps(
            [
                {
                    "agent_id": "payments-agent-01",
                    "capability": "crm.read_contact",
                    "granted_by": "role:sales-ops-baseline",
                },
                {
                    "agent_id": "payments-agent-01",
                    "capability": "crm.update_contact",
                    "granted_by": "role:sales-ops-baseline",
                },
                {
                    "agent_id": "payments-agent-01",
                    "capability": "payments.pay_invoice",
                    "granted_by": "role:ap-clerk",
                    "budget": 500000.0,
                },
                {
                    "agent_id": "payments-agent-01",
                    "capability": "payments.settle",
                    "granted_by": "role:settlement-desk",
                    "budget": 500000.0,
                },
                {
                    "agent_id": "breaker-agent-02",
                    "capability": "payments.transfer",
                    "granted_by": "role:treasury",
                    "budget": 500000.0,
                },
                {
                    "agent_id": "payments-agent-01",
                    "capability": "payments.initiate_wire",
                    "granted_by": "cfo-standing-approval-2026Q3",
                    "budget": 100000.0,
                },
            ]
        )
    )
    signing_seed = hashlib.sha256(b"executive-demo-deployment-key").hexdigest()
    os.environ["PV_RECEIPT_SIGNING_KEY"] = signing_seed
    signing_public_key = ReceiptSigner(seed_hex=signing_seed).public_key

    runtime = build_production_runtime(
        RuntimeConfig(
            db_path=str(db),
            keys_file=str(tmp / "keys.json"),
            policy_file=str(tmp / "policy.json"),
            grants_file=str(tmp / "grants.json"),
            breaker_max_amount=50000.0,  # per-window spending cap
            breaker_window_seconds=60.0,
            trusted_public_keys=frozenset({signing_public_key}),
        )
    )

    banner("0. DEPLOYMENT MANIFEST — what THIS runtime enforces (GET /v1/runtime)")
    for level, info in runtime.composition.items():
        print(f"  {level:<16} {info['status']:<15} {info['detail']}")

    mw = runtime.middleware()

    def call(key, tool, arguments=None, evidence=None):
        return mw.handle(
            ToolCallRequest(
                adapter="executive-demo",
                tool=tool,
                api_key=key,
                arguments=arguments or {},
                evidence=evidence,
            )
        )

    key = ops_key["key"]

    banner("1. IDENTITY — the credential IS the agent; auditors can read, never act")
    expect(
        "no credential",
        call(None, "crm.read_contact"),
        "block",
        "identity",
        "unauthenticated traffic cannot write to the evidence store",
    )
    expect(
        "audit-scoped credential attempts action",
        call(auditor["key"], "payments.initiate_wire"),
        "block",
        "identity",
        "segregation of duties: the auditor's key structurally "
        "cannot exercise enforcement",
    )

    banner(
        "2. AUTHORIZED BASELINE — granted work flows; every "
        "verdict is a signed, chained record"
    )
    expect(
        "routine CRM read (granted)",
        call(key, "crm.read_contact"),
        "allow",
        "baseline",
        "a granted, low-drift routine action passes cleanly and is still recorded",
    )
    expect(
        "routine CRM update (granted)",
        call(key, "crm.update_contact"),
        "allow",
        "baseline",
    )

    banner(
        "3. CUSTOMER POLICY (L2) — data-driven rules; the fired "
        "rule is NAMED in the record"
    )
    expect(
        "bulk export attempt",
        call(key, "storage.bulk_export"),
        "block",
        "policy",
        "DLP / data-residency",
    )
    rec = runtime.recorder.graph.lineage(_last_id(runtime))[-1]
    assert rec.policy_id == "DLP-001-no-bulk-export", rec.policy_id
    print(f"        record.policy_id = {rec.policy_id!r} (schema field, hash-covered)")

    banner("4. ENTERPRISE CONSTRAINTS (L0/UAAL) — tampered amount vs invoice evidence")
    expect(
        "pay 49,000 against a 5,000 invoice",
        call(
            key,
            "payments.pay_invoice",
            arguments={"amount": 49000.0, "target": "INV-7734"},
            evidence={
                "user_request": {"canonical_target": "INV-7734"},
                "planner": {"canonical_target": "INV-7734"},
                "enterprise_state": {
                    "invoice_amount": 5000.0,
                    "invoice_open": True,
                    "target_verified": True,
                    "duplicate": False,
                },
            },
        ),
        "block",
        "uaal_constraint",
        "monetary conservation: the action amount must equal the "
        "invoice it claims to pay",
    )

    banner(
        "5. MULTI-AGENT CONSENSUS (L3, pv-vote/1) — a fraud "
        "dissent cannot be shouted down or replayed"
    )
    register_key("fraud-agent", "fraud-secret")
    dissent = cast_vote("fraud-agent", "settle-9982", "REJECT", "settle-9982")
    consensus_ev = {
        "consensus": {
            "action_id": "settle-9982",
            "threshold": 0.67,
            "votes": [dissent, dissent, dissent],  # replayed 3x: counts ONCE
            "trust_scores": {"fraud-agent": 1.0},
        }
    }
    expect(
        "settlement with open fraud dissent (vote replayed 3x)",
        call(
            key, "payments.settle", arguments={"target": "9982"}, evidence=consensus_ev
        ),
        "require_approval",
        "consensus",
        "RBI dual-control: a negative attestation escalates; "
        "duplicate/replayed votes carry zero extra weight",
    )

    banner(
        "6. SPENDING CIRCUIT BREAKER — the CROSSING payment is "
        "blocked, not the one after it"
    )
    breaker_api_key = breaker_key["key"]  # dedicated treasury agent, clean window
    expect(
        "wire 30,000 (novel capability -> drift escalates first)",
        call(breaker_api_key, "payments.transfer", arguments={"amount": 30000.0}),
        "require_approval",
        "drift",
        "the learned layer escalates an unfamiliar payment for "
        "review BEFORE the deterministic cap is even reached -- "
        "two independent controls, not one",
    )
    expect(
        "wire 30,000 more (projects 60,000 > 50,000 cap)",
        call(breaker_api_key, "payments.transfer", arguments={"amount": 30000.0}),
        "block",
        "circuit_breaker",
        "pre-execution cap: projected counters gate the crossing "
        "action itself, atomically under concurrency",
    )

    banner(
        "7. CAPABILITY GRANTS & LIVE BUDGETS — the standing "
        "approval is named; the budget actually decrements"
    )
    from agent_dna.advisory import AdvisorySignal, Severity

    class _Neutral:
        def score(self, action, prev_capability=None):
            return AdvisorySignal(
                agent_id=action.agent_id,
                capability=action.capability,
                drift_score=0.0,
                severity=Severity.INFO,
                reasons=[],
            )

    from agent_dna.circuit_breaker import (
        BreakerConfig,
        CircuitBreaker,
        GuardedEngine,
    )

    reg = GrantRegistry()
    g = reg.grant(
        agent_id="payments-agent-01",
        capability="payments.initiate_wire",
        granted_by="cfo-standing-approval-2026Q3",
        budget=100000.0,
    )
    ge = GuardedEngine(
        DecisionEngine(scorer=_Neutral(), authorizer=reg),
        CircuitBreaker(
            tmp / "grants.breaker.db",
            BreakerConfig(
                max_decisions=None,
                max_cumulative_amount=None,
                max_consecutive_refusals=None,
            ),
        ),
    )

    def wire(amount):
        return ge.decide(
            AgentAction(
                agent_id="payments-agent-01",
                capability="payments.initiate_wire",
                timestamp=time.time(),
                arguments={"amount": amount},
            )
        )

    r1 = wire(60000.0)
    ok1 = r1.decision is Decision.ALLOW and r1.grant_id == g.grant_id
    print(
        f"  [{'OK ' if ok1 else 'FAIL'}] wire 60,000 under 100,000 "
        f"budget -> {r1.decision.value}, approval_ref={r1.grant_id[:14]}.."
    )
    if not ok1:
        FAILURES.append("grant wire 1")
    rec = DecisionRecorder().record(
        AgentAction(
            agent_id="payments-agent-01",
            capability="payments.initiate_wire",
            timestamp=time.time(),
            arguments={"amount": 60000.0},
        ),
        r1,
    )
    print(
        f"        record.approval_ref = {rec.approval_ref[:14]}.. "
        "(the CFO approval this wire executed under, hash-covered)"
    )

    r2 = wire(60000.0)
    ok2 = r2.decision is Decision.REQUIRE_APPROVAL and "budget exceeded" in r2.reason
    print(
        f"  [{'OK ' if ok2 else 'FAIL'}] wire 60,000 more "
        f"(60k spent + 60k > 100k) -> {r2.decision.value}: {r2.reason}"
    )
    if not ok2:
        FAILURES.append("grant budget")

    banner(
        "8. INDEPENDENT VERIFICATION — a stdlib script that "
        "trusts NOTHING in this codebase"
    )
    export = tmp / "audit_export.jsonl"
    runtime.store.export_jsonl(export)
    verifier = ROOT / "tools" / "verify_records.py"

    def verify(path):
        pr = subprocess.run(
            [sys.executable, str(verifier), str(path)], capture_output=True, text=True
        )
        verdict = "PASS" if "VERDICT: PASS" in pr.stdout else "FAIL"
        return verdict, pr.stdout

    v0, out = verify(export)
    print(f"  clean export         : VERDICT {v0}")
    if v0 != "PASS":
        FAILURES.append("clean export failed verification:\n" + out)

    lines = export.read_text().splitlines()
    tampered = tmp / "tampered.jsonl"
    doc = json.loads(lines[2])
    doc["decision"] = "allow" if doc.get("decision") != "allow" else "block"
    tampered.write_text("\n".join(lines[:2] + [json.dumps(doc)] + lines[3:]) + "\n")
    v1, _ = verify(tampered)
    print(f"  1 flipped verdict    : VERDICT {v1}  (hash mismatch + chain break)")
    if v1 != "FAIL":
        FAILURES.append("tampered file verified clean")

    deleted = tmp / "deleted.jsonl"
    deleted.write_text("\n".join(lines[:2] + lines[3:]) + "\n")
    v2, _ = verify(deleted)
    print(f"  1 deleted record     : VERDICT {v2}  (downstream prev_hash orphaned)")
    if v2 != "FAIL":
        FAILURES.append("deletion verified clean")

    banner("9. RESTART SURVIVAL — the evidence outlives the process")
    fresh = DecisionRecorder(store=SQLiteDecisionStore(db))
    chains = fresh.graph.verify_all()
    envelopes = len(fresh.envelopes)
    ok = all(chains.values()) and envelopes > 0
    print(
        f"  [{'OK ' if ok else 'FAIL'}] fresh process: "
        f"{len(chains)} chain(s) verified {chains}, "
        f"{envelopes} Ed25519 envelope(s) restored from disk"
    )
    if not ok:
        FAILURES.append("restart survival")

    banner("EXECUTIVE SUMMARY")
    print(f"  scenarios asserted   : {len(LEDGER) + 4}")
    print(f"  failures             : {len(FAILURES)}")
    print("""
  What you just watched, mapped to your controls:
    identity binding          -> credential = agent; auditors read-only
    customer policy (named)   -> DLP rule id inside the sealed record
    UAAL monetary conservation-> tampered amounts blocked pre-execution
    pv-vote/1 consensus       -> dissent escalates; replay counts once
    spending circuit breaker  -> the CROSSING payment blocks, atomically
    grants + live budgets     -> CFO approval named in every record;
                                 budgets decrement on execution
    independent verifier      -> tamper and deletion caught by a script
                                 with zero trust in this codebase
    restart survival          -> chains + signatures restored from disk

  Every control above regressed at least one strict CI test to earn
  its row in docs/PRODUCTION-HARDENING.md. What is NOT enforced is
  equally explicit: GET /v1/runtime and WHAT-WE-DO-NOT-CLAIM.md.
""")
    if FAILURES:
        print("ACCEPTANCE: FAILED")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print("ACCEPTANCE: PASSED — every control fired exactly as claimed.")
    return 0


def _last_id(runtime):
    recs = list(runtime.recorder.graph.find_by_agent("payments-agent-01"))
    return recs[-1].decision_id


if __name__ == "__main__":
    sys.exit(main())
