from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from agent_dna.governance.evaluate import (
    combine_evaluations,
    evaluate_control,
    evaluate_pack,
)
from agent_dna.governance.pack import (
    CitationStatus,
    DeploymentProfile,
    Lifecycle,
    Pack,
    Result,
    load_pack,
)

PACK_DIR = (
    Path(__file__).resolve().parents[1]
    / "agent_dna"
    / "governance"
    / "packs"
)
ACTION_CLASS = "payment_execution"
RISK_TIER = "high"


def _entity_type_for(mapping: Pack, customer: Pack) -> str:
    candidates = {
        "bank",
        "retail-bank",
        "schedule-i-bank",
        "financial-institution",
        "licensed-financial-institution",
        "federally-regulated-financial-institution",
    }

    for pack in (mapping, customer):
        for control in pack.controls:
            candidates.update(control.applicability.entity_types)

    ranked: list[tuple[int, str]] = []

    for candidate in candidates:
        mapping_count = len(
            mapping.applicable(
                candidate,
                ACTION_CLASS,
                RISK_TIER,
            )
        )
        customer_count = len(
            customer.applicable(
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

    assert ranked, "No entity type makes both packs applicable"
    ranked.sort(key=lambda item: (-item[0], item[1]))
    return ranked[0][1]


def _facts(
    destination: str,
    allowed: bool,
    packs: tuple[Pack, ...],
) -> dict[str, Any]:
    facts: dict[str, Any] = {
        "action_class": ACTION_CLASS,
        "risk_tier": RISK_TIER,
        "amount": 6000,
        "currency": "USD",
        "destination_country": destination if allowed else "SG",
        "approved_destination_countries": [destination],
        "model_id": "payment-risk-model-v4",
        "model_approval_status": "approved" if allowed else "pending",
        "model_inventory_id": "MI-3391",
        "independent_review_status": "completed",
        "residual_risk_status": "accepted",
        "ai_governance_framework_status": "documented",
        "board_oversight_status": "recorded",
        "technology_register_status": "registered",
        "risk_alignment_status": "pending-human-review",
        "approval_id": "APR-TEST-0042",
        "approver_identity": "controller@example.test",
    }

    for pack in packs:
        for control in pack.controls:
            for field_name in control.evidence_required:
                facts.setdefault(
                    field_name,
                    f"test-{field_name}-captured",
                )

    return facts


@pytest.mark.parametrize(
    ("mapping_file", "jurisdiction", "regulator"),
    [
        ("canada-osfi.yaml", "CA", "OSFI"),
        ("uae-financial.yaml", "AE", "CBUAE"),
    ],
)
@pytest.mark.parametrize(
    ("allowed", "expected"),
    [
        (False, Result.BLOCK),
        (True, Result.PASS),
    ],
)
def test_readiness_mapping_cannot_change_enforcement(
    mapping_file: str,
    jurisdiction: str,
    regulator: str,
    allowed: bool,
    expected: Result,
) -> None:
    mapping = load_pack(PACK_DIR / mapping_file)
    customer = load_pack(
        PACK_DIR / "customer-internal-policy.yaml"
    )

    entity_type = _entity_type_for(mapping, customer)

    profile = DeploymentProfile(
        organisation="Synthetic Test Bank",
        jurisdiction=jurisdiction,
        entity_type=entity_type,
        regulator=regulator,
        data_residency=jurisdiction,
        packs=(mapping.pack_id, customer.pack_id),
    )

    facts = _facts(
        jurisdiction,
        allowed,
        (mapping, customer),
    )

    mapping_result = evaluate_pack(
        mapping,
        profile,
        ACTION_CLASS,
        RISK_TIER,
        facts,
    )
    customer_result = evaluate_pack(
        customer,
        profile,
        ACTION_CLASS,
        RISK_TIER,
        facts,
    )

    assert mapping_result.result is Result.REVIEW
    assert mapping_result.enforced_result is Result.NOT_APPLICABLE
    assert not any(item.binding for item in mapping_result.controls)

    assert customer_result.enforced_result is expected
    assert combine_evaluations(
        [mapping_result, customer_result]
    ) is expected


def test_non_active_would_block_becomes_non_binding_review() -> None:
    customer = load_pack(
        PACK_DIR / "customer-internal-policy.yaml"
    )
    active = next(
        control
        for control in customer.controls
        if control.control_id == "ORG-MODEL-APPROVED-001"
    )
    draft = replace(active, lifecycle=Lifecycle.DRAFT)

    result = evaluate_control(
        draft,
        {
            "model_approval_status": "pending",
        },
    )

    assert result.proposed_result is Result.BLOCK
    assert result.result is Result.REVIEW
    assert result.binding is False


def test_active_control_rejects_unverified_source() -> None:
    customer = load_pack(
        PACK_DIR / "customer-internal-policy.yaml"
    )
    active = customer.controls[0]
    unverified_source = replace(
        active.source,
        citation_status=CitationStatus.UNVERIFIED,
    )

    with pytest.raises(
        ValueError,
        match="cannot be ACTIVE with an unverified citation",
    ):
        replace(active, source=unverified_source)


def test_bundle_hash_covers_decision_semantics() -> None:
    pack = load_pack(
        PACK_DIR / "customer-internal-policy.yaml"
    )
    original = pack.bundle_hash()
    control = pack.controls[0]
    remaining = pack.controls[1:]

    variants = [
        replace(
            control,
            assertion=f"({control.assertion}) and True",
        ),
        replace(
            control,
            lifecycle=Lifecycle.SIGNED,
        ),
        replace(
            control,
            approved_by=control.approved_by + "-changed",
        ),
        replace(
            control,
            source=replace(
                control.source,
                document=control.source.document + " amended",
            ),
        ),
        replace(
            control,
            applicability=replace(
                control.applicability,
                risk_tiers=(
                    control.applicability.risk_tiers
                    | frozenset({"__hash_test_tier__"})
                ),
            ),
        ),
        replace(
            control,
            evidence_required=(
                *control.evidence_required,
                "additional_evidence",
            ),
        ),
    ]

    for changed_control in variants:
        changed_pack = replace(
            pack,
            controls=[changed_control, *remaining],
        )
        assert changed_pack.bundle_hash() != original

    reordered = replace(
        pack,
        controls=list(reversed(pack.controls)),
    )
    assert reordered.bundle_hash() == original


def test_requirement_order_does_not_change_bundle_hash() -> None:
    pack = load_pack(PACK_DIR / "canada-osfi.yaml")

    reordered = replace(
        pack,
        requirements=dict(
            reversed(list(pack.requirements.items()))
        ),
    )

    assert reordered.bundle_hash() == pack.bundle_hash()


def test_requirement_change_changes_bundle_hash() -> None:
    pack = load_pack(PACK_DIR / "canada-osfi.yaml")
    requirement_id = next(iter(pack.requirements))
    requirement = pack.requirements[requirement_id]

    changed_requirements = dict(pack.requirements)
    changed_requirements[requirement_id] = replace(
        requirement,
        effective_from="2099-01-01",
    )
    changed = replace(
        pack,
        requirements=changed_requirements,
    )

    assert changed.bundle_hash() != pack.bundle_hash()
