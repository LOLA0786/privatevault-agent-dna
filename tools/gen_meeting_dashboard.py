#!/usr/bin/env python3
"""Render every collected test as a regulated-finance scenario map.

Reads real pytest collection. Maps each node ID to an enforcement stage and a
BFSI use case via explicit ordered rules below. Tests that match no rule are
reported as UNMAPPED, never forced into a bucket.
"""

import json, re, subprocess, sys, time, html
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "meeting-dashboard.html"

# ---------------------------------------------------------------- use cases
# Each rule: (use_case_id, regex over full node id). Ordered, first match wins.
# Patterns key off ACTUAL file/function names. Edit freely; unmapped is visible.
USE_CASES = [
    (
        "payment_release",
        "Payment authorization & release",
        "APRA CPS 230 · critical operation",
        r"payment|payout|transfer|settle|disburse",
    ),
    (
        "refund_authority",
        "Refund & chargeback authority",
        "Maker-checker · SOX",
        r"refund|chargeback|reversal",
    ),
    (
        "dual_control",
        "Multi-agent dual control",
        "Four-eyes · DIFC Reg 10",
        r"dual_control|consensus|maker_checker|multi_agent|quorum",
    ),
    (
        "evidence_export",
        "Audit evidence & regulator export",
        "CPS 230 record-keeping",
        r"audit|evidence|export|attest|seal|receipt|merkle|chain",
    ),
    (
        "credential_scope",
        "Credential scope & key authority",
        "PCI DSS · least privilege",
        r"apikey|api_key|credential|token|scope|secret|grant",
    ),
    (
        "identity_auth",
        "Agent identity & authority derivation",
        "Non-repudiation",
        r"identity|authority|principal|actor|fingerprint|attribut",
    ),
    (
        "anomaly_contain",
        "Anomaly detection & containment",
        "Operational resilience",
        r"anomaly|adversarial|injection|drift|egress|abuse|hostile",
    ),
    (
        "policy_decision",
        "Policy decision & invariant enforcement",
        "Board-approved risk appetite",
        r"policy|invariant|rule|opa|rego|constraint|advisory",
    ),
    (
        "permit_mint",
        "Pre-execution permit minting",
        "The authorization boundary",
        r"permit|mint|action_digest|drp|seal_decision|authorize",
    ),
    (
        "dispatch_exec",
        "Execution dispatch & closure",
        "Complete mediation",
        r"dispatch|execut|gateway|connector|closure|sidecar|mcp",
    ),
    (
        "limits_velocity",
        "Limits, velocity & rate control",
        "Exposure caps",
        r"limit|rate|throttle|budget|velocity|cap",
    ),
    (
        "data_access",
        "Customer data access scope",
        "Privacy Act · GDPR",
        r"privacy|pii|redact|tenant|isolation|data_scope",
    ),
    (
        "resilience",
        "Resilience & failure modes",
        "CPS 230 tolerance levels",
        r"fail_closed|failclosed|timeout|retry|degrade|recover|resilien",
    ),
]

STAGES = [
    ("identity", r"identity|authority|principal|fingerprint"),
    ("invariants", r"invariant"),
    ("policy", r"policy|opa|rego|advisory|rule"),
    ("approval", r"approval|dual_control|maker_checker|quorum"),
    ("grants", r"grant|apikey|api_key|credential|token"),
    ("limits", r"limit|rate|throttle|budget"),
    ("anomaly", r"anomaly|adversarial|injection|drift|egress"),
    ("permit mint", r"permit|mint|action_digest|drp|seal"),
    ("dispatch", r"dispatch|execut|gateway|connector|sidecar|mcp"),
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
        line = line.strip()
        m = re.match(r"^(\d+) tests? collected", line)
        if m:
            total = int(m.group(1))
            continue
        if "::" in line and not line.startswith(("=", "-", "ERROR", "warning")):
            ids.append(line)
    return ids, total, r.stdout.strip().splitlines()[-1] if r.stdout else ""


def classify(node, rules):
    low = node.lower()
    for entry in rules:
        if re.search(entry[-1], low):
            return entry[0]
    return None


def main():
    t0 = time.time()
    ids, total, last = collect()
    if not ids:
        sys.exit("no tests collected — run pytest manually to see the error")

    uc_meta = {u[0]: {"id": u[0], "name": u[1], "anchor": u[2]} for u in USE_CASES}
    buckets = defaultdict(list)
    unmapped = []

    for n in ids:
        path, _, fn = n.partition("::")
        uc = classify(n, USE_CASES)
        st = classify(n, STAGES)
        rec = {"id": n, "file": path, "fn": fn, "stage": st or "unassigned"}
        if uc:
            buckets[uc].append(rec)
        else:
            unmapped.append(rec)

    payload = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "collected": total if total is not None else len(ids),
        "enumerated": len(ids),
        "collectLine": last,
        "runtime": round(time.time() - t0, 2),
        "useCases": [
            {**uc_meta[u[0]], "tests": buckets.get(u[0], [])}
            for u in USE_CASES
            if buckets.get(u[0])
        ],
        "unmapped": unmapped,
    }

    tpl = (ROOT / "tools" / "meeting_dashboard.template.html").read_text()
    OUT.write_text(tpl.replace("__PAYLOAD__", json.dumps(payload)))

    mapped = len(ids) - len(unmapped)
    print(f"wrote {OUT.name}")
    print(f"collected: {payload['collected']}  enumerated: {len(ids)}")
    print(
        f"mapped to use case: {mapped}  unmapped: {len(unmapped)} "
        f"({mapped / len(ids) * 100:.1f}% mapped)"
    )
    if unmapped:
        print("\nsample unmapped (tighten USE_CASES rules for these):")
        for r in unmapped[:15]:
            print("  " + r["id"])


if __name__ == "__main__":
    main()
