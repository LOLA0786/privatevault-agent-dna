"""Governance control packs.

A regulation is not enforcement. It becomes enforcement only after a
named human converts it into a testable assertion, and the pack records
who did that and against which source. Nothing here reads a PDF.

Every control declares how it can be checked at all:

  runtime       evaluable per action; can BLOCK or REVIEW
  evidence      does not block; the named artefacts must be captured
  assessment    answered once per organisation, not per action
  human_review  requires legal or professional judgement; always REVIEW

The distinction that keeps this honest is `status`: binding law, issued
regulation, guidance, draft guidance, industry framework and internal
policy are not the same thing, and a draft must never be rendered as an
obligation.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class Mode(StrEnum):
    RUNTIME = "runtime"
    EVIDENCE = "evidence"
    ASSESSMENT = "assessment"
    HUMAN_REVIEW = "human_review"


class Status(StrEnum):
    """Force of the underlying source. Ordered weakest to strongest."""

    INTERNAL_POLICY = "internal-policy"
    INDUSTRY_FRAMEWORK = "industry-framework"
    FRAMEWORK_REPORT = "framework-report"
    DRAFT_GUIDANCE = "draft-guidance"
    GUIDANCE = "guidance"
    REGULATION = "regulation"
    LAW = "law"


class CitationStatus(StrEnum):
    """Whether a human has checked the citation against the source.

    UNVERIFIED is the default and it is deliberately loud. A control
    whose citation nobody has confirmed may still be evaluated -- but it
    cannot enforce. See Lifecycle.
    """

    UNVERIFIED = "unverified"
    VERIFIED = "verified"
    DISPUTED = "disputed"


class Lifecycle(StrEnum):
    """How far a control has travelled from source text to enforceable rule.

    Only ACTIVE may produce an enforced verdict. Everything earlier is a
    proposal: the engine still evaluates it and still reports what it
    would have decided, but the decision does not bind. A pack that
    announces its own uncertainty and enforces anyway is worse than one
    that tracks nothing, because the field implies something is checking.
    """

    DRAFT = "draft"
    SOURCE_VERIFIED = "source-verified"
    EXPERT_MAPPED = "expert-mapped"
    CUSTOMER_APPROVED = "customer-approved"
    SIGNED = "signed"
    ACTIVE = "active"
    RETIRED = "retired"

    @property
    def enforceable(self) -> bool:
        return self is Lifecycle.ACTIVE


class Result(StrEnum):
    PASS = "PASS"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"
    NOT_APPLICABLE = "NOT_APPLICABLE"


# Most restrictive wins. Order matters.
_SEVERITY = [Result.BLOCK, Result.REVIEW, Result.PASS, Result.NOT_APPLICABLE]


def most_restrictive(results: Sequence[Result]) -> Result:
    for candidate in _SEVERITY:
        if candidate in results:
            return candidate
    return Result.NOT_APPLICABLE


@dataclass(frozen=True)
class Source:
    authority: str
    document: str
    jurisdiction: str
    status: Status
    citation: str = ""
    citation_status: CitationStatus = CitationStatus.UNVERIFIED
    source_url: str = ""
    source_hash: str = ""
    retrieved_at: str = ""

    def label(self) -> str:
        note = (
            ""
            if self.citation_status is CitationStatus.VERIFIED
            else f"  [citation {self.citation_status.value}]"
        )
        return f"{self.authority} - {self.document} ({self.status.value}){note}"


@dataclass(frozen=True)
class Applicability:
    entity_types: frozenset[str] = frozenset()
    action_classes: frozenset[str] = frozenset()
    risk_tiers: frozenset[str] = frozenset()

    def covers(self, entity_type: str, action_class: str, risk_tier: str) -> bool:
        return (
            (not self.entity_types or entity_type in self.entity_types)
            and (not self.action_classes or action_class in self.action_classes)
            and (not self.risk_tiers or risk_tier in self.risk_tiers)
        )


@dataclass(frozen=True)
class SourceRequirement:
    """What the regulator actually published. Never executable by itself.

    Kept separate from the control so a receipt can say "blocked by
    customer-approved control ORG-X, mapped to OSFI E-23" and never
    "OSFI blocked the action". The regulator did not block anything;
    a control someone approved did.
    """

    requirement_id: str  # SRC-CA-OSFI-E23
    source: Source
    effective_from: str = ""  # ISO date; empty means already in force

    def in_force(self, on_date: str) -> bool:
        return not self.effective_from or on_date >= self.effective_from


@dataclass(frozen=True)
class Control:
    control_id: str  # ORG-... : an executable control, not a law
    title: str
    source: Source
    applicability: Applicability
    mode: Mode
    lifecycle: Lifecycle = Lifecycle.DRAFT
    mapped_requirements: tuple[str, ...] = ()  # SRC- ids this derives from
    required_facts: tuple[str, ...] = ()
    assertion: str = ""
    evidence_required: tuple[str, ...] = ()
    missing_fact_result: Result = Result.REVIEW
    failed_control_result: Result = Result.BLOCK
    interpretation_owner: str = ""
    approved_by: str = ""

    def __post_init__(self) -> None:
        if self.mode is Mode.RUNTIME and not self.assertion:
            raise ValueError(f"{self.control_id}: runtime control needs an assertion")
        if self.mode is Mode.RUNTIME and not self.interpretation_owner:
            raise ValueError(
                f"{self.control_id}: runtime control needs a named "
                f"interpretation owner -- nobody enforces an unattributed reading"
            )
        if self.lifecycle is Lifecycle.ACTIVE:
            if self.source.citation_status is not CitationStatus.VERIFIED:
                raise ValueError(
                    f"{self.control_id}: cannot be ACTIVE with an "
                    f"{self.source.citation_status.value} citation"
                )
            if not self.approved_by:
                raise ValueError(
                    f"{self.control_id}: cannot be ACTIVE without a named approver"
                )


@dataclass
class Pack:
    pack_id: str
    version: str
    jurisdiction: str
    title: str
    controls: list[Control] = field(default_factory=list)
    requirements: dict[str, SourceRequirement] = field(default_factory=dict)
    notes: str = ""

    def requirement_labels(self, control: Control) -> list[str]:
        out = []
        for rid in control.mapped_requirements:
            req = self.requirements.get(rid)
            out.append(f"{rid} ({req.source.document})" if req else rid)
        return out

    def bundle_hash(self) -> str:
        """Hash every decision-relevant field in the governance pack.

        A changed assertion, lifecycle, approver, source, applicability rule
        or evidence requirement must produce a different bundle hash.
        Control and requirement ordering does not affect the hash.
        """
        import hashlib
        import json

        def source_payload(source: Source) -> dict[str, Any]:
            return {
                "authority": source.authority,
                "document": source.document,
                "jurisdiction": source.jurisdiction,
                "status": source.status.value,
                "citation": source.citation,
                "citation_status": source.citation_status.value,
                "source_url": source.source_url,
                "source_hash": source.source_hash,
                "retrieved_at": source.retrieved_at,
            }

        requirements = [
            {
                "requirement_id": requirement.requirement_id,
                "effective_from": requirement.effective_from,
                "source": source_payload(requirement.source),
            }
            for requirement in sorted(
                self.requirements.values(),
                key=lambda item: item.requirement_id,
            )
        ]

        controls = [
            {
                "control_id": control.control_id,
                "title": control.title,
                "source": source_payload(control.source),
                "applicability": {
                    "entity_types": sorted(control.applicability.entity_types),
                    "action_classes": sorted(control.applicability.action_classes),
                    "risk_tiers": sorted(control.applicability.risk_tiers),
                },
                "mode": control.mode.value,
                "lifecycle": control.lifecycle.value,
                "mapped_requirements": sorted(control.mapped_requirements),
                "required_facts": list(control.required_facts),
                "assertion": control.assertion,
                "evidence_required": list(control.evidence_required),
                "missing_fact_result": control.missing_fact_result.value,
                "failed_control_result": control.failed_control_result.value,
                "interpretation_owner": control.interpretation_owner,
                "approved_by": control.approved_by,
            }
            for control in sorted(
                self.controls,
                key=lambda item: item.control_id,
            )
        ]

        canonical = json.dumps(
            {
                "pack_id": self.pack_id,
                "version": self.version,
                "jurisdiction": self.jurisdiction,
                "title": self.title,
                "notes": self.notes,
                "source_requirements": requirements,
                "controls": controls,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    def applicable(
        self, entity_type: str, action_class: str, risk_tier: str
    ) -> list[Control]:
        return [
            c
            for c in self.controls
            if c.applicability.covers(entity_type, action_class, risk_tier)
        ]

    def unverified_citations(self) -> list[Control]:
        return [
            c
            for c in self.controls
            if c.source.citation_status is not CitationStatus.VERIFIED
        ]


@dataclass(frozen=True)
class DeploymentProfile:
    """What the customer told us they are. Controls are filtered by this."""

    organisation: str
    jurisdiction: str
    entity_type: str
    regulator: str = ""
    data_residency: str = ""
    packs: tuple[str, ...] = ()
    high_impact_default: Result = Result.REVIEW


def _build_source(src: dict[str, Any]) -> Source:
    return Source(
        authority=src["authority"],
        document=src["document"],
        jurisdiction=src["jurisdiction"],
        status=Status(src["status"]),
        citation=src.get("citation", ""),
        citation_status=CitationStatus(src.get("citation_status", "unverified")),
        source_url=src.get("source_url", ""),
        source_hash=src.get("source_hash", ""),
        retrieved_at=src.get("retrieved_at", ""),
    )


def load_pack(path: str | Path) -> Pack:
    """Load a pack from YAML. Kept import-light: PyYAML only if used."""
    import yaml

    raw: dict[str, Any] = yaml.safe_load(Path(path).read_text(encoding="utf-8"))

    requirements: dict[str, SourceRequirement] = {}
    for item in raw.get("source_requirements", []):
        requirements[item["requirement_id"]] = SourceRequirement(
            requirement_id=item["requirement_id"],
            effective_from=item.get("effective_from", ""),
            source=_build_source(item["source"]),
        )

    controls: list[Control] = []
    for item in raw.get("controls", []):
        app = item.get("applicability", {})
        controls.append(
            Control(
                control_id=item["control_id"],
                title=item["title"],
                source=_build_source(item["source"]),
                applicability=Applicability(
                    entity_types=frozenset(app.get("entity_types", [])),
                    action_classes=frozenset(app.get("action_classes", [])),
                    risk_tiers=frozenset(app.get("risk_tiers", [])),
                ),
                mode=Mode(item["mode"]),
                lifecycle=Lifecycle(item.get("lifecycle", "draft")),
                mapped_requirements=tuple(item.get("mapped_requirements", [])),
                required_facts=tuple(item.get("required_facts", [])),
                assertion=item.get("assertion", ""),
                evidence_required=tuple(item.get("evidence_required", [])),
                missing_fact_result=Result(item.get("missing_fact_result", "REVIEW")),
                failed_control_result=Result(
                    item.get("failed_control_result", "BLOCK")
                ),
                interpretation_owner=item.get("interpretation_owner", ""),
                approved_by=item.get("approved_by", ""),
            )
        )

    return Pack(
        pack_id=raw["pack_id"],
        version=str(raw["version"]),
        jurisdiction=raw["jurisdiction"],
        title=raw["title"],
        controls=controls,
        requirements=requirements,
        notes=raw.get("notes", ""),
    )
