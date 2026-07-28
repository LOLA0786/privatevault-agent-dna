#!/usr/bin/env python3
"""Demonstrate authority denial, detection, and post-grant allow."""

from __future__ import annotations

import json
from pathlib import Path

from agent_dna.authority_v01 import (
    scan_authority_records,
    verify_receipt,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
VECTORS = (
    REPO_ROOT
    / "spec"
    / "authority-v01"
    / "vectors"
)


def load_vector(name: str) -> dict:
    path = VECTORS / name
    return json.loads(path.read_text(encoding="utf-8"))


def show(label: str, filename: str) -> None:
    vector = load_vector(filename)
    receipt = vector["receipt"]

    report = verify_receipt(
        receipt,
        vector["trust_bundle"],
    )

    print()
    print(label)
    print("-" * len(label))
    print("business checks       PASS")
    print(
        "requested action      "
        f"{receipt['requested']['action']}"
    )
    print(
        "requested resource    "
        f"{receipt['requested']['resource']}"
    )
    print(
        "authority verdict     "
        f"{receipt['authority_result']['verdict']}"
    )
    print(
        "authority reason      "
        f"{receipt['authority_result']['reason_code']}"
    )
    print(
        "policy verdict        "
        f"{receipt['policy_result']['verdict']}"
    )
    print(
        "final verdict         "
        f"{receipt['final_verdict']}"
    )
    print(
        "evidence              "
        f"{report.evidence_state.value}"
    )
    print(
        "conformance           "
        f"{report.decision_conformance.value}"
    )

    grant = receipt["grant_chain"][-1]
    print(
        "accountable grant     "
        f"{grant['grant_id']}"
    )
    print(
        "accountable issuer    "
        f"{grant['issuer_principal']}"
    )


def main() -> None:
    print(
        "PRIVATEVAULT AUTHORITY DERIVATION DEMO"
    )
    print("=" * 64)
    print(
        "The business policy allows every scenario. "
        "Signed delegated authority determines whether "
        "the action may execute."
    )

    show(
        "1. BEFORE GRANT — BUSINESS CHECKS PASS, AUTHORITY DENIES",
        "denied-outside-authority.json",
    )

    show(
        "2. INJECTED VARIANT — AUTHORITY RESULT IS UNCHANGED",
        "injected-variant.json",
    )

    show(
        "3. RECORDED OUT-OF-AUTHORITY ALLOW",
        "allowed-outside-authority.json",
    )

    nonconformant = load_vector(
        "allowed-outside-authority.json"
    )
    scan = scan_authority_records(
        [nonconformant["receipt"]],
        nonconformant["trust_bundle"],
    )

    print(
        "scanner finding       "
        f"{scan['critical_findings'][0]['finding']}"
    )

    show(
        "4. AFTER CASE-SCOPED 10-MINUTE GRANT",
        "after-grant.json",
    )

    print()
    print("CUSTOMER PROOF")
    print("-" * 64)
    print(
        "Before grant : policy ALLOW + authority DENY "
        "=> final DENY"
    )
    print(
        "False allow  : evidence VERIFIED + decision "
        "NON_CONFORMANT"
    )
    print(
        "After grant  : policy ALLOW + authority ALLOW "
        "=> final ALLOW"
    )


if __name__ == "__main__":
    main()
