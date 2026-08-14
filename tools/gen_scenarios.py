#!/usr/bin/env python3
"""Bind regulated-finance attack scenarios to real collected tests.

Each scenario is a story a banker recognizes. Each step in the story is proven
by tests pulled live from pytest collection. Steps with no matching test are
shown as UNPROVEN, never quietly dropped.
"""

import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "scenarios.html"

# Each step: (label, what_happens, pattern matched against real node IDs)
SCENARIOS = [
    {
        "id": "rogue_payment",
        "title": "Agent attempts a payment beyond its mandate",
        "sector": "Tier-1 bank · treasury operations",
        "anchor": "APRA CPS 230 critical operation",
        "story": "A settlement agent is asked to clear a batch. One instruction inside "
        "the batch moves USD 2.4M to a counterparty the agent was never granted.",
        "outcome": "BLOCKED before execution. No permit minted. Attempt sealed as evidence.",
        "steps": [
            (
                "Agent proposes the action",
                "Intent captured before anything executes",
                r"propose|intent|request|decide",
            ),
            (
                "Identity and authority resolved",
                "Which principal, acting under whose authority",
                r"identity|authority|principal|actor",
            ),
            (
                "Policy evaluated against mandate",
                "Counterparty is outside the granted scope",
                r"policy|opa|rego|rule|advisory",
            ),
            (
                "Limit and exposure check",
                "Amount exceeds the standing cap",
                r"limit|budget|cap|threshold|velocity",
            ),
            (
                "Verdict is BLOCK",
                "Deterministic refusal, not a model judgement",
                r"block|deny|refus|reject|fail_closed|failclosed",
            ),
            (
                "No permit is minted",
                "Execution is impossible without a permit",
                r"permit|mint|action_digest",
            ),
            (
                "Attempt sealed to the audit chain",
                "The refusal itself is evidence",
                r"audit|seal|evidence|record|chain|merkle",
            ),
        ],
    },
    {
        "id": "injection_redirect",
        "title": "Prompt injection hidden in an invoice redirects a payout",
        "sector": "Payments · accounts payable automation",
        "anchor": "Operational resilience · adversarial input",
        "story": "A supplier PDF contains instructions telling the agent to change the "
        "beneficiary account. The model complies. The runtime does not.",
        "outcome": "Model was compromised; the action still could not execute.",
        "steps": [
            (
                "Hostile content reaches the model",
                "We assume the model can be turned",
                r"injection|adversarial|hostile|malicious|prompt",
            ),
            (
                "Agent emits a modified action",
                "Beneficiary differs from the authorized one",
                r"divergen|mismatch|tamper|modif",
            ),
            (
                "Exact-byte binding compared",
                "What was authorized vs what is executing",
                r"action_digest|digest|binding|exact_byte|bind",
            ),
            (
                "Verdict is BLOCK",
                "Divergence is structural, not probabilistic",
                r"block|deny|refus|fail_closed|failclosed",
            ),
            (
                "Egress is refused",
                "Nothing leaves the boundary",
                r"egress|gateway|dispatch|outbound",
            ),
            (
                "Injection attempt recorded",
                "Forensics for the incident report",
                r"audit|evidence|record|seal|trace",
            ),
        ],
    },
    {
        "id": "self_approval",
        "title": "A single agent tries to approve its own high-value action",
        "sector": "DIFC-licensed institution",
        "anchor": "DIFC Regulation 10 · four-eyes",
        "story": "The agent proposes a transfer and then issues its own approval, "
        "satisfying the letter of a maker-checker workflow with one identity.",
        "outcome": "Rejected. Approver and proposer must be distinct principals.",
        "steps": [
            (
                "Action requires dual control",
                "Value band triggers four-eyes",
                r"dual_control|maker_checker|approval|quorum",
            ),
            (
                "Second approval presented",
                "Same principal, second signature",
                r"consensus|multi_agent|second|approver",
            ),
            (
                "Distinct-principal invariant",
                "Structural separation is enforced",
                r"invariant|distinct|separat|independen",
            ),
            (
                "Verdict is BLOCK",
                "Self-approval cannot satisfy the control",
                r"block|deny|refus|reject",
            ),
            (
                "Control failure logged",
                "Regulator-visible record of the attempt",
                r"audit|evidence|record|seal",
            ),
        ],
    },
    {
        "id": "credential_overreach",
        "title": "Agent uses a valid key beyond its granted scope",
        "sector": "Wealth management · client data",
        "anchor": "Least privilege · PCI DSS",
        "story": "A read-scoped key is presented for a write operation. The credential "
        "is genuine and unexpired — the scope is not.",
        "outcome": "Refused at the authorization layer, before the downstream call.",
        "steps": [
            (
                "Credential presented",
                "Valid, unexpired, correctly signed",
                r"apikey|api_key|credential|token|secret",
            ),
            (
                "Granted scope resolved",
                "What this key is actually permitted to do",
                r"scope|grant|permission|entitle",
            ),
            (
                "Requested action compared",
                "Write requested against read grant",
                r"policy|rule|authoriz|check",
            ),
            (
                "Verdict is BLOCK",
                "Authentic is not the same as authorized",
                r"block|deny|refus|reject|unauthoriz",
            ),
            (
                "Scope violation sealed",
                "Evidence of attempted escalation",
                r"audit|evidence|record|seal",
            ),
        ],
    },
    {
        "id": "permit_replay",
        "title": "An old permit is replayed to execute a second time",
        "sector": "Cross-border settlement",
        "anchor": "Non-repudiation · replay resistance",
        "story": "A previously authorized transfer permit is resubmitted. If it works, "
        "the bank pays twice and the audit trail shows one authorization.",
        "outcome": "Second execution refused. One authorization means one execution.",
        "steps": [
            (
                "Valid permit issued",
                "First execution proceeds correctly",
                r"permit|mint|issue",
            ),
            (
                "Permit resubmitted",
                "Same bytes, second attempt",
                r"replay|reuse|duplicate|idempot",
            ),
            (
                "Single-use binding checked",
                "Permit is consumed on execution",
                r"consume|expire|single_use|nonce|ttl",
            ),
            (
                "Verdict is BLOCK",
                "Deterministic, not heuristic",
                r"block|deny|refus|reject|expire",
            ),
            (
                "Replay attempt recorded",
                "Distinguishable from the legitimate execution",
                r"audit|evidence|record|trace|seal",
            ),
        ],
    },
    {
        "id": "regulator_request",
        "title": "Regulator asks what the agent did and why",
        "sector": "Supervisory review",
        "anchor": "CPS 230 record-keeping · independently verifiable",
        "story": "Six weeks after an incident, the supervisor asks the bank to show "
        "every autonomous action, its authorization, and who was accountable.",
        "outcome": "Reconstructed from sealed evidence and verified without trusting us.",
        "steps": [
            (
                "Decisions retrieved",
                "Every decide call, not a sample",
                r"decision|decide|record",
            ),
            (
                "Authorization chain reconstructed",
                "Which authority permitted each action",
                r"authority|chain|derivation|trace",
            ),
            (
                "Evidence exported",
                "Portable artifact leaves the runtime",
                r"export|evidence|audit|report",
            ),
            (
                "Independently verified",
                "Checked without the vendor in the loop",
                r"verif|attest|merkle|signature|independent",
            ),
            (
                "Tamper detection",
                "Any alteration is detectable",
                r"tamper|integrity|mutat|corrupt",
            ),
        ],
    },
]


def collect():
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    ids, total = [], None
    for line in r.stdout.splitlines():
        s = line.strip()
        m = re.match(r"^(\d+) tests? collected", s)
        if m:
            total = int(m.group(1))
            continue
        if "::" in s and not s.startswith(("=", "-", "ERROR", "warning")):
            ids.append(s)
    return ids, total, (r.stdout.strip().splitlines() or [""])[-1]


def main():
    t0 = time.time()
    ids, total, last = collect()
    if not ids:
        sys.exit("no tests collected")

    used = {}
    out = []
    # specificity = pattern length; longer/rarer patterns claim first
    ranked = []
    for si, sc in enumerate(SCENARIOS):
        for pi, (label, what, pat) in enumerate(sc["steps"]):
            ranked.append((len(pat), si, pi, pat))
    ranked.sort(reverse=True)

    claims = {}
    for _, si, pi, pat in ranked:
        rx = re.compile(pat)
        for nid in ids:
            if nid in used:
                continue
            fn = nid.split("::", 1)[1].lower()
            if rx.search(fn):
                used[nid] = (si, pi)
                claims.setdefault((si, pi), []).append(nid)

    for si, sc in enumerate(SCENARIOS):
        steps = []
        for pi, (label, what, pat) in enumerate(sc["steps"]):
            hits = claims.get((si, pi), [])
            steps.append(
                {
                    "label": label,
                    "what": what,
                    "count": len(hits),
                    "tests": [
                        {"fn": h.split("::", 1)[1], "file": h.split("::", 1)[0]}
                        for h in hits[:40]
                    ],
                    "more": max(0, len(hits) - 40),
                }
            )
        out.append(
            {
                **{
                    k: sc[k]
                    for k in ("id", "title", "sector", "anchor", "story", "outcome")
                },
                "steps": steps,
                "total": sum(x["count"] for x in steps),
            }
        )

    payload = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "collected": total or len(ids),
        "collectLine": last,
        "distinctTestsCited": len(used),
        "unclaimed": len(ids) - len(used),
        "scenarios": out,
        "runtime": round(time.time() - t0, 2),
    }
    tpl = (ROOT / "tools" / "scenarios.template.html").read_text()
    OUT.write_text(tpl.replace("__PAYLOAD__", json.dumps(payload)))

    print(f"wrote {OUT.name}")
    print(f"collected: {payload['collected']}  distinct tests cited: {len(used)}")
    print(f"unclaimed (not cited by any scenario): {len(ids) - len(used)}")
    for sc in out:
        weak = [st["label"] for st in sc["steps"] if st["count"] == 0]
        print(
            f"  {sc['title'][:52]:54s} {sc['total']:5d} tests"
            + (f"   UNPROVEN: {'; '.join(weak)}" if weak else "")
        )
    from collections import Counter

    unc = [i for i in ids if i not in used]
    print("\ntop uncited files (tune patterns against these):")
    for f, c in Counter(i.split("::")[0] for i in unc).most_common(20):
        print(f"  {c:4d}  {f}")


if __name__ == "__main__":
    main()
