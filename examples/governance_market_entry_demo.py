"""PrivateVault governance market-entry demonstration.

The demonstration proves a strict separation:

1. Regulatory mappings describe readiness and remain non-binding.
2. Only a customer's ACTIVE internal policy affects execution.
3. The same action can therefore be:
   - BLOCKED by active customer controls; or
   - ALLOWED when those controls pass.
4. Every decision records the complete bundle hashes used.

This is synthetic demonstration evidence. It is not a claim of regulatory
compliance and does not treat regulatory guidance as executable law.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent_dna.governance.evaluate import (  # noqa: E402
    GovernanceEvaluation,
    combine_evaluations,
    evaluate_pack,
)
from agent_dna.governance.pack import (  # noqa: E402
    DeploymentProfile,
    Pack,
    Result,
    load_pack,
)

PACK_DIR = ROOT / "agent_dna" / "governance" / "packs"
ACTION_CLASS = "payment_execution"
RISK_TIER = "high"

MARKETS = {
    "ca": {
        "name": "Canadian Schedule I Bank",
        "jurisdiction": "CA",
        "regulator": "OSFI",
        "mapping_file": "canada-osfi.yaml",
        "currency": "USD",
        "local_destination": "CA",
    },
    "ae": {
        "name": "UAE Retail Bank",
        "jurisdiction": "AE",
        "regulator": "CBUAE",
        "mapping_file": "uae-financial.yaml",
        "currency": "USD",
        "local_destination": "AE",
    },
}

VERDICT_LABEL = {
    Result.PASS: "ALLOW",
    Result.REVIEW: "REVIEW",
    Result.BLOCK: "BLOCK",
    Result.NOT_APPLICABLE: "NOT_APPLICABLE",
}


def canonical_hash(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def choose_entity_type(
    mapping_pack: Pack,
    customer_pack: Pack,
) -> str:
    """Choose an entity type that makes both packs applicable."""

    candidates = {
        "bank",
        "retail-bank",
        "schedule-i-bank",
        "financial-institution",
        "licensed-financial-institution",
        "federally-regulated-financial-institution",
    }

    for pack in (mapping_pack, customer_pack):
        for control in pack.controls:
            candidates.update(control.applicability.entity_types)

    ranked: list[tuple[int, str]] = []

    for candidate in candidates:
        mapping_count = len(
            mapping_pack.applicable(
                candidate,
                ACTION_CLASS,
                RISK_TIER,
            )
        )
        customer_count = len(
            customer_pack.applicable(
                candidate,
                ACTION_CLASS,
                RISK_TIER,
            )
        )

        if mapping_count and customer_count:
            ranked.append(
                (
                    mapping_count + customer_count,
                    candidate,
                )
            )

    if not ranked:
        raise RuntimeError(
            "No entity type makes both the readiness mapping and "
            "customer policy applicable."
        )

    ranked.sort(key=lambda item: (-item[0], item[1]))
    return ranked[0][1]


def scenario_facts(
    market_code: str,
    allowed: bool,
    packs: tuple[Pack, ...],
) -> dict[str, Any]:
    market = MARKETS[market_code]

    facts: dict[str, Any] = {
        "action_class": ACTION_CLASS,
        "risk_tier": RISK_TIER,
        "amount": 6000,
        "currency": market["currency"],
        "cross_border": not allowed,
        "destination_country": (
            market["local_destination"] if allowed else "SG"
        ),
        "approved_destination_countries": [
            market["local_destination"],
        ],
        "model_id": "payment-risk-model-v4",
        "model_approval_status": "approved" if allowed else "pending",
        "model_inventory_id": "MI-3391",
        "independent_review_status": "completed",
        "residual_risk_status": "accepted",
        "ai_governance_framework_status": "documented",
        "board_oversight_status": "recorded",
        "technology_register_status": "registered",
        "risk_alignment_status": "pending-human-review",
        "approval_id": "APR-2026-0729-0042",
        "approver_identity": "treasury-controller@example.test",
    }

    # Supply synthetic evidence markers for evidence-mode controls.
    # These names come from the packs themselves, so the demonstration
    # remains valid if an evidence field is added or renamed.
    for pack in packs:
        for control in pack.controls:
            for field_name in control.evidence_required:
                facts.setdefault(
                    field_name,
                    f"synthetic-{field_name}-captured",
                )

    return facts


def print_controls(
    evaluation: GovernanceEvaluation,
    readiness: bool,
) -> None:
    for item in evaluation.controls:
        if readiness:
            print(
                f"  {item.result.value:<14} "
                f"{item.control_id:<48} "
                f"lifecycle={item.lifecycle.value:<17} "
                f"proposed={item.proposed_result.value:<14} "
                f"binding={item.binding}"
            )
        else:
            print(
                f"  {item.result.value:<7} "
                f"{item.control_id:<48} "
                f"binding={item.binding}"
            )


def make_receipt(
    market_code: str,
    scenario: str,
    profile: DeploymentProfile,
    facts: dict[str, Any],
    mapping: GovernanceEvaluation,
    customer: GovernanceEvaluation,
    final_result: Result,
) -> dict[str, Any]:
    decision_input = {
        "action_class": ACTION_CLASS,
        "risk_tier": RISK_TIER,
        "amount": facts["amount"],
        "currency": facts["currency"],
        "destination_country": facts["destination_country"],
        "model_id": facts["model_id"],
        "model_approval_status": facts["model_approval_status"],
        "approval_id": facts["approval_id"],
        "approver_identity": facts["approver_identity"],
    }

    receipt_body = {
        "receipt_spec": "pv-governance-demo-receipt/0.1",
        "evidence_class": "synthetic-demonstration",
        "market": market_code.upper(),
        "scenario": scenario,
        "organisation": profile.organisation,
        "entity_type": profile.entity_type,
        "decision_input": decision_input,
        "decision_input_digest": canonical_hash(decision_input),
        "business_policy_result": "PASS",
        "delegated_authority_result": "PASS",
        "readiness_mapping": {
            "pack_id": mapping.pack_id,
            "pack_version": mapping.pack_version,
            "bundle_hash": mapping.bundle_hash,
            "display_result": mapping.result.value,
            "enforced_result": mapping.enforced_result.value,
            "binding": False,
        },
        "customer_policy": {
            "pack_id": customer.pack_id,
            "pack_version": customer.pack_version,
            "bundle_hash": customer.bundle_hash,
            "display_result": customer.result.value,
            "enforced_result": customer.enforced_result.value,
            "binding": True,
        },
        "final_verdict": VERDICT_LABEL[final_result],
        "claim_boundary": (
            "Regulatory mapping is readiness evidence only. "
            "The final verdict is determined only by ACTIVE "
            "customer-approved controls."
        ),
    }

    body_digest = canonical_hash(receipt_body)

    return {
        "receipt_id": "pvr_demo_" + body_digest.split(":", 1)[1][:16],
        **receipt_body,
        "receipt_digest": body_digest,
    }


def run_scenario(
    market_code: str,
    scenario: str,
    customer_pack: Pack,
) -> None:
    market = MARKETS[market_code]
    mapping_pack = load_pack(PACK_DIR / market["mapping_file"])
    allowed = scenario == "allowed"

    entity_type = choose_entity_type(mapping_pack, customer_pack)

    profile = DeploymentProfile(
        organisation=f"Synthetic {market['name']}",
        jurisdiction=market["jurisdiction"],
        entity_type=entity_type,
        regulator=market["regulator"],
        data_residency=market["jurisdiction"],
        packs=(mapping_pack.pack_id, customer_pack.pack_id),
    )

    facts = scenario_facts(
        market_code,
        allowed,
        (mapping_pack, customer_pack),
    )

    mapping_evaluation = evaluate_pack(
        mapping_pack,
        profile,
        ACTION_CLASS,
        RISK_TIER,
        facts,
    )
    customer_evaluation = evaluate_pack(
        customer_pack,
        profile,
        ACTION_CLASS,
        RISK_TIER,
        facts,
    )

    final_result = combine_evaluations(
        [mapping_evaluation, customer_evaluation]
    )

    print()
    print("=" * 96)
    print(
        f"{market_code.upper()}  {market['name']}  |  "
        f"scenario: {scenario.upper()}"
    )
    print("=" * 96)
    print(f"Action              {ACTION_CLASS}")
    print(f"Risk tier           {RISK_TIER}")
    print(
        f"Attempted effect    {facts['amount']} {facts['currency']} "
        f"to {facts['destination_country']}"
    )
    print(
        f"Model               {facts['model_id']} "
        f"(approval: {facts['model_approval_status']})"
    )
    print("Business policy     PASS")
    print("Delegated authority PASS")
    print()
    print(
        f"{market['regulator']} READINESS MAPPING — "
        "VISIBLE, BUT DOES NOT BIND"
    )
    print("-" * 96)
    print_controls(mapping_evaluation, readiness=True)
    print(
        f"  Display result:   {mapping_evaluation.result.value}"
    )
    print(
        f"  Enforced result:  "
        f"{mapping_evaluation.enforced_result.value}"
    )
    print(
        f"  Bundle hash:      {mapping_evaluation.bundle_hash}"
    )

    print()
    print("CUSTOMER INTERNAL POLICY — ACTIVE AND BINDING")
    print("-" * 96)
    print_controls(customer_evaluation, readiness=False)
    print(
        f"  Enforced result:  "
        f"{customer_evaluation.enforced_result.value}"
    )
    print(
        f"  Bundle hash:      {customer_evaluation.bundle_hash}"
    )

    print()
    print(f"FINAL VERDICT       {VERDICT_LABEL[final_result]}")
    print(
        "Decision basis      ACTIVE customer policy; "
        "regulatory mapping did not alter enforcement"
    )

    receipt = make_receipt(
        market_code,
        scenario,
        profile,
        facts,
        mapping_evaluation,
        customer_evaluation,
        final_result,
    )

    print()
    print("TAMPER-EVIDENT DECISION EVIDENCE")
    print("-" * 96)
    print(json.dumps(receipt, indent=2, sort_keys=True))

    assert mapping_evaluation.result is Result.REVIEW
    assert mapping_evaluation.enforced_result is Result.NOT_APPLICABLE

    if allowed:
        assert customer_evaluation.enforced_result is Result.PASS
        assert final_result is Result.PASS
    else:
        assert customer_evaluation.enforced_result is Result.BLOCK
        assert final_result is Result.BLOCK


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Show non-binding regulatory readiness mappings alongside "
            "binding customer governance controls."
        )
    )
    parser.add_argument(
        "--market",
        choices=("ca", "ae", "all"),
        default="all",
    )
    parser.add_argument(
        "--case",
        choices=("blocked", "allowed", "all"),
        default="all",
    )
    args = parser.parse_args()

    customer_pack = load_pack(
        PACK_DIR / "customer-internal-policy.yaml"
    )

    markets = ("ca", "ae") if args.market == "all" else (args.market,)
    scenarios = (
        ("blocked", "allowed")
        if args.case == "all"
        else (args.case,)
    )

    print("=" * 96)
    print("PRIVATEVAULT GOVERNANCE MARKET-ENTRY DEMO")
    print("Regulatory mappings propose. Customer policy binds.")
    print("=" * 96)

    for market_code in markets:
        for scenario in scenarios:
            run_scenario(
                market_code,
                scenario,
                customer_pack,
            )

    print()
    print("=" * 96)
    print("DEMO ASSERTIONS: PASS")
    print(
        "Non-binding mappings stayed visible but could not alter "
        "any execution verdict."
    )
    print()
    print("WHAT THIS DOES")
    print(
        "Evaluates customer-approved controls, records the exact "
        "bundle hashes and emits tamper-evident decision evidence."
    )
    print()
    print("WHAT THIS DOES NOT CLAIM")
    print(
        "It does not make an institution OSFI- or CBUAE-compliant. "
        "The mappings require expert verification and customer approval."
    )
    print("=" * 96)


if __name__ == "__main__":
    main()
