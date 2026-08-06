"""Offline, low-compute discovery loop for PrivateVault controls.

The online enforcement path is deliberately absent from this module.  A run:

1. verifies and mines sealed decision history for candidate controls;
2. evaluates each candidate additively against history and a committed
   adversarial corpus;
3. runs optional structural and advisory-validation probes;
4. ranks candidates with a deterministic triage heuristic; and
5. emits evidence-linked, human-reviewable proposal files.

No candidate is applied.  ``PROPOSE`` means "ready to open a pull request",
not "authorized to change policy".  Models are neither required nor imported.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from .policy.checker import PolicyChecker
from .policy.schema import parse_policy_dict
from .policy_gate import run_assertions
from .policy_miner import RuleCandidate, mine
from .security.loop_discovery import discover_loops
from .validation.metrics import wilson_interval

DISCOVERY_REPORT_SPEC = "pv-discovery-loop-report/1.0"
ADVERSARIAL_ROW_SPEC = "pv-discovery-adversarial-row/1.0"

_DECISIONS = frozenset({"allow", "block", "require_approval"})
_LABELS = frozenset({"attack", "benign"})
_DIGEST_PREFIX = "sha256:"
_RECORD_HASH = re.compile(r"^[0-9a-f]{64}$")
_UNSAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")
MAX_ADVERSARIAL_FIXTURE_BYTES = 64 * 1024 * 1024
MAX_ADVERSARIAL_ROW_BYTES = 1 * 1024 * 1024


class DiscoveryInputError(ValueError):
    """The experiment cannot proceed safely without guessing."""


class CandidateDisposition(StrEnum):
    PROPOSE = "PROPOSE"
    REVIEW = "REVIEW"
    REJECT = "REJECT"
    ADVISORY = "ADVISORY"


class DiscoveryStatus(StrEnum):
    NO_CHANGE = "NO_CHANGE"
    PROPOSALS_READY = "PROPOSALS_READY"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    STRUCTURAL_BLOCK = "STRUCTURAL_BLOCK"


@dataclass(frozen=True, slots=True)
class DiscoveryConfig:
    min_support: int = 5
    numeric_field: str = "amount"
    since_ts: float | None = None
    max_new_blocks: int = 0
    max_candidates: int = 100
    max_history_records: int = 100_000
    max_adversarial_rows: int = 10_000
    as_of: float = 0.0

    def __post_init__(self) -> None:
        if self.min_support < 1:
            raise DiscoveryInputError("min_support must be >= 1")
        if not self.numeric_field or len(self.numeric_field) > 128:
            raise DiscoveryInputError("numeric_field must be 1..128 characters")
        if self.max_new_blocks < 0:
            raise DiscoveryInputError("max_new_blocks must be >= 0")
        if not 1 <= self.max_candidates <= 1000:
            raise DiscoveryInputError("max_candidates must be in [1, 1000]")
        if not 1 <= self.max_history_records <= 1_000_000:
            raise DiscoveryInputError("max_history_records must be in [1, 1000000]")
        if not 1 <= self.max_adversarial_rows <= 100_000:
            raise DiscoveryInputError("max_adversarial_rows must be in [1, 100000]")
        for name, value in (("since_ts", self.since_ts), ("as_of", self.as_of)):
            if value is not None and (not math.isfinite(value) or value < 0):
                raise DiscoveryInputError(f"{name} must be a finite non-negative value")


@dataclass(frozen=True, slots=True)
class CandidateExperiment:
    candidate_id: str
    kind: str
    severity: str
    capability: str
    support: int
    candidate_digest: str
    policy_digest: str | None
    evidence_record_hashes: tuple[str, ...]
    assertions: dict[str, Any]
    history: dict[str, Any]
    adversarial: dict[str, Any]
    disposition: CandidateDisposition
    priority_score: int
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["disposition"] = self.disposition.value
        value["evidence_record_hashes"] = list(self.evidence_record_hashes)
        value["reasons"] = list(self.reasons)
        return value


@dataclass(slots=True)
class DiscoveryResult:
    envelope: dict[str, Any]
    proposal_documents: dict[str, dict[str, Any]]

    @property
    def status(self) -> DiscoveryStatus:
        return DiscoveryStatus(self.envelope["body"]["status"])

    @property
    def report_hash(self) -> str:
        return str(self.envelope["report_hash"])

    def write_proposals(self, output_dir: str | Path) -> list[Path]:
        """Write only PR-ready policies plus evidence-review notes."""
        target = Path(output_dir)
        target.mkdir(parents=True, exist_ok=True)
        experiments = {
            item["candidate_id"]: item for item in self.envelope["body"]["experiments"]
        }
        written: list[Path] = []
        for candidate_id in sorted(self.proposal_documents):
            experiment = experiments[candidate_id]
            safe_id = _UNSAFE_FILENAME.sub("-", candidate_id).strip("._-")
            safe_id = (safe_id or "candidate")[:96]
            suffix = experiment["candidate_digest"].removeprefix(_DIGEST_PREFIX)[:12]
            stem = f"{safe_id}-{suffix}"
            policy_path = target / f"{stem}.json"
            review_path = target / f"{stem}.proposal.md"
            policy_path.write_text(
                json.dumps(self.proposal_documents[candidate_id], indent=2) + "\n",
                encoding="utf-8",
            )
            hashes = experiment["evidence_record_hashes"]
            evidence = "\n".join(f"- `{record_hash}`" for record_hash in hashes)
            review_path.write_text(
                "\n".join(
                    [
                        "# PrivateVault Discovery proposal",
                        "",
                        "Human approval is required. This file is not an authorization.",
                        "",
                        f"- Discovery report: `{self.report_hash}`",
                        f"- Candidate ID: `{json.dumps(candidate_id)}`",
                        f"- Candidate digest: `{experiment['candidate_digest']}`",
                        f"- Priority score: `{experiment['priority_score']}` (triage only)",
                        f"- Capability: `{experiment['capability']}`",
                        f"- Support: `{experiment['support']}` sealed decisions",
                        "",
                        "## Evaluation reasons",
                        "",
                        *(f"- {reason}" for reason in experiment["reasons"]),
                        "",
                        "## Motivating sealed record hashes",
                        "",
                        evidence or "- None recorded",
                        "",
                        "## Required review",
                        "",
                        "- [ ] Named policy owner confirms intent and scope.",
                        "- [ ] Counterfactual divergence budget is acknowledged.",
                        "- [ ] Adversarial and assertion results are reviewed.",
                        "- [ ] Standard policy-gate CI passes before merge.",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            written.extend((policy_path, review_path))
        return written


def canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise DiscoveryInputError(f"value is not canonical JSON: {exc}") from exc


def digest(value: object) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(canonical_json(value).encode()).hexdigest()


def load_adversarial_fixture(path: str | Path) -> list[dict[str, Any]]:
    source = Path(path)
    try:
        if source.stat().st_size > MAX_ADVERSARIAL_FIXTURE_BYTES:
            raise DiscoveryInputError(
                f"adversarial fixture exceeds {MAX_ADVERSARIAL_FIXTURE_BYTES} bytes"
            )
        lines = source.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise DiscoveryInputError(
            f"cannot read adversarial fixture {path}: {exc}"
        ) from exc

    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        if len(line.encode("utf-8")) > MAX_ADVERSARIAL_ROW_BYTES:
            raise DiscoveryInputError(
                f"{path}:{line_number}: row exceeds {MAX_ADVERSARIAL_ROW_BYTES} bytes"
            )
        try:
            value = json.loads(
                line,
                parse_constant=lambda token: (_ for _ in ()).throw(
                    ValueError(f"non-finite number {token}")
                ),
            )
        except (json.JSONDecodeError, ValueError) as exc:
            raise DiscoveryInputError(
                f"{path}:{line_number}: invalid JSON: {exc}"
            ) from exc
        rows.append(_validate_adversarial_row(value, f"{path}:{line_number}"))

    ids = [row["id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise DiscoveryInputError("adversarial fixture contains duplicate row ids")
    return sorted(rows, key=lambda row: row["id"])


def _validate_adversarial_row(  # noqa: C901 - strict wire validation
    value: object, path: str
) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(k, str) for k in value):
        raise DiscoveryInputError(f"{path}: expected object with string keys")
    expected = {
        "spec",
        "id",
        "label",
        "agent_id",
        "capability",
        "arguments",
        "evidence",
        "baseline_decision",
    }
    if set(value) != expected:
        raise DiscoveryInputError(
            f"{path}: fields must be exactly {sorted(expected)}, got {sorted(value)}"
        )
    for field in ("spec", "id", "label", "agent_id", "capability", "baseline_decision"):
        if not isinstance(value[field], str) or not value[field]:
            raise DiscoveryInputError(f"{path}.{field}: expected non-empty string")
    for field in ("id", "agent_id", "capability"):
        if len(value[field]) > 256:
            raise DiscoveryInputError(f"{path}.{field}: exceeds 256 characters")
    if value["spec"] != ADVERSARIAL_ROW_SPEC:
        raise DiscoveryInputError(f"{path}.spec: unsupported value {value['spec']!r}")
    if value["label"] not in _LABELS:
        raise DiscoveryInputError(f"{path}.label: expected one of {sorted(_LABELS)}")
    if value["baseline_decision"] not in _DECISIONS:
        raise DiscoveryInputError(
            f"{path}.baseline_decision: expected one of {sorted(_DECISIONS)}"
        )
    if not isinstance(value["arguments"], dict):
        raise DiscoveryInputError(f"{path}.arguments: expected object")
    if value["evidence"] is not None and not isinstance(value["evidence"], dict):
        raise DiscoveryInputError(f"{path}.evidence: expected object or null")
    if len(canonical_json(value).encode()) > MAX_ADVERSARIAL_ROW_BYTES:
        raise DiscoveryInputError(
            f"{path}: canonical row exceeds {MAX_ADVERSARIAL_ROW_BYTES} bytes"
        )
    return dict(value)


def _checker(candidate: RuleCandidate) -> tuple[PolicyChecker, list[dict[str, Any]]]:
    if candidate.policy_document is None:
        raise DiscoveryInputError(f"candidate {candidate.id} has no policy document")
    raw = json.loads(canonical_json(candidate.policy_document))
    assertions = raw.pop("assertions", [])
    if not isinstance(assertions, list):
        raise DiscoveryInputError(
            f"candidate {candidate.id}: assertions must be a list"
        )
    if any(
        rule.get("outcome") not in {"block", "require_approval"}
        for rule in raw.get("policies", [])
    ):
        raise DiscoveryInputError(
            f"candidate {candidate.id}: discovery policies must be escalation-only"
        )
    return PolicyChecker(parse_policy_dict(raw)), assertions


def _history_rows(
    decision_store: Any,
    replay_store: Any | None,
    since_ts: float | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records = list(decision_store.iter_decisions(since_ts))
    by_id = {record["decision_id"]: record for record in records}
    retained: dict[str, dict[str, Any]] = {}
    replay_identity: list[dict[str, Any]] = []
    if replay_store is not None and getattr(replay_store, "enabled", False):
        # Select the time window from the sealed decision timestamp, not the
        # separately captured replay timestamp. The two commits are related
        # but deliberately live in different stores.
        for row in replay_store.iter_inputs(None):
            record = by_id.get(row["decision_id"])
            if record is None:
                if decision_store.get_decision(row["decision_id"]) is not None:
                    continue
                raise DiscoveryInputError(
                    f"replay input {row['decision_id']} has no sealed decision record"
                )
            if (row["agent_id"], row["capability"]) != (
                record["agent_id"],
                record["capability"],
            ):
                raise DiscoveryInputError(
                    f"replay input {row['decision_id']} identity does not match "
                    "the sealed decision"
                )
            expected_scope = sorted(set(replay_store.retain_fields))
            if row.get("field_scope") != expected_scope:
                raise DiscoveryInputError(
                    f"replay input {row['decision_id']} field scope does not match "
                    "the declared replay scope"
                )
            if not isinstance(row["retained"], dict) or not set(row["retained"]) <= set(
                expected_scope
            ):
                raise DiscoveryInputError(
                    f"replay input {row['decision_id']} exceeds its declared field scope"
                )
            retained[row["decision_id"]] = dict(row["retained"])
            replay_identity.append(
                {
                    "decision_id": row["decision_id"],
                    "retained_digest": digest(row["retained"]),
                }
            )

    rows = [
        {
            "id": record["decision_id"],
            "agent_id": record["agent_id"],
            "capability": record["capability"],
            "arguments": retained.get(record["decision_id"], {}),
            "evidence": None,
            "baseline_decision": record["decision"],
            "record_hash": record["record_hash"],
            "has_replay": record["decision_id"] in retained,
        }
        for record in records
    ]
    return rows, sorted(replay_identity, key=lambda item: item["decision_id"])


def _row_matches_rule(row: dict[str, Any], rule: dict[str, Any]) -> bool:
    return rule.get("capability") in ("*", row["capability"]) and rule.get(
        "agent_id"
    ) in (None, row["agent_id"])


def _missing_history_evidence(
    candidate: RuleCandidate, rows: list[dict[str, Any]]
) -> tuple[str, ...]:
    missing: set[str] = set()
    for rule in (candidate.policy_document or {}).get("policies", []):
        condition = rule.get("condition")
        if not condition:
            continue
        field = condition.get("field", "")
        if not isinstance(field, str) or "." not in field:
            continue
        root, name = field.split(".", 1)
        for row in rows:
            if not _row_matches_rule(row, rule):
                continue
            source = row.get(root)
            if not isinstance(source, dict) or name not in source:
                missing.add(row["id"])
    return tuple(sorted(missing))


def _evaluate_additive(  # noqa: C901 - one-pass audit accounting is intentional
    checker: PolicyChecker,
    rows: list[dict[str, Any]],
    *,
    labeled: bool,
) -> dict[str, Any]:
    escalations: list[str] = []
    covered_refusals: list[str] = []
    benign_escalations: list[str] = []
    errors: list[str] = []
    attack_n = benign_n = attack_covered = benign_preserved = 0

    for row in rows:
        if labeled:
            if row["label"] == "attack":
                attack_n += 1
            else:
                benign_n += 1
        try:
            result = checker.check(
                agent_id=row["agent_id"],
                capability=row["capability"],
                arguments=row["arguments"],
                evidence=row["evidence"],
            )
        except Exception as exc:  # noqa: BLE001 - recorded and rejects candidate
            errors.append(f"{row['id']}:{type(exc).__name__}")
            continue

        fired = bool(result.fired)
        if fired and row["baseline_decision"] == "allow":
            escalations.append(row["id"])
        elif fired:
            covered_refusals.append(row["id"])

        if labeled and row["label"] == "attack" and fired:
            attack_covered += 1
        if labeled and row["label"] == "benign" and not fired:
            benign_preserved += 1
        if (
            labeled
            and row["label"] == "benign"
            and fired
            and row["baseline_decision"] == "allow"
        ):
            benign_escalations.append(row["id"])

    def interval(successes: int, total: int) -> list[float] | None:
        return list(wilson_interval(successes, total)) if total else None

    return {
        "state": "complete",
        "evaluated": len(rows),
        "new_escalations": len(escalations),
        "covered_refusals": len(covered_refusals),
        "benign_escalations": len(benign_escalations),
        "candidate_errors": len(errors),
        "sample_new_escalation_ids": escalations[:10],
        "sample_covered_refusal_ids": covered_refusals[:10],
        "sample_benign_escalation_ids": benign_escalations[:10],
        "error_ids": errors[:10],
        "attack_rows": attack_n,
        "attack_covered": attack_covered,
        "attack_coverage_wilson_95": interval(attack_covered, attack_n),
        "benign_rows": benign_n,
        "benign_preserved": benign_preserved,
        "benign_preservation_wilson_95": interval(benign_preserved, benign_n),
        "semantics": "additive_candidate_never_relaxes_existing_levels",
    }


def _assertion_summary(
    checker: PolicyChecker, assertions: list[dict[str, Any]]
) -> dict[str, Any]:
    results = run_assertions(checker, assertions)
    return {
        "declared": len(results),
        "passed": sum(result.passed for result in results),
        "failed": sum(not result.passed for result in results),
        "failures": [
            {
                "name": result.name,
                "expected": result.expected,
                "actual": result.actual,
            }
            for result in results
            if not result.passed
        ],
    }


def _loop_probe(events: list[dict[str, object]] | None) -> dict[str, Any]:
    if events is None:
        return {"state": "ABSENT", "effect": "no structural loop evidence supplied"}
    report = discover_loops(events)
    return {
        "state": "VERIFIED",
        "decision": report.decision.value,
        "report_id": report.report_id,
        "input_digest": report.input_digest,
        "findings": len(report.findings),
        "reason_codes": sorted({finding.reason_code for finding in report.findings}),
        "effect": "BLOCK and REVIEW are hard filters for policy proposals",
    }


def _validation_probe(envelope: dict[str, Any] | None, as_of: float) -> dict[str, Any]:
    if envelope is None:
        return {
            "state": "ABSENT",
            "effect": "advisory drift validation is orthogonal to deterministic policy",
        }
    try:
        if set(envelope) != {"body", "report_hash"}:
            raise ValueError("envelope fields must be body and report_hash")
        body = envelope["body"]
        if not isinstance(body, dict):
            raise ValueError("body must be an object")
        claimed = envelope["report_hash"]
        actual = hashlib.sha256(canonical_json(body).encode()).hexdigest()
        if claimed != actual:
            raise ValueError("report hash mismatch")
        if body.get("format") != "pv-validation/1":
            raise ValueError("unsupported validation format")
        dataset = body.get("dataset", {})
        if dataset.get("label_source") != "independent":
            raise ValueError("validation labels are not independently sourced")
        if not str(dataset.get("label_source_note", "")).strip():
            raise ValueError("validation label source note is empty")
        expired = body.get("expires_at", 0) < as_of
        return {
            "state": "EXPIRED" if expired else "VERIFIED",
            "report_hash": claimed,
            "score_name": body.get("score", {}).get("name"),
            "score_type": body.get("score", {}).get("type"),
            "auc": (body.get("global") or {}).get("auc"),
            "effect": "advisory_only; never authorizes or relaxes deterministic policy",
        }
    except (KeyError, TypeError, ValueError, DiscoveryInputError) as exc:
        return {
            "state": "INVALID",
            "reason": str(exc),
            "effect": "advisory_only; deterministic candidate evaluation continues",
        }


def _priority(
    candidate: RuleCandidate, history: dict[str, Any], adversarial: dict[str, Any]
) -> int:
    severity = {"HIGH": 10_000, "MEDIUM": 5_000}.get(candidate.severity, 0)
    return max(
        0,
        severity
        + min(candidate.support, 1000) * 10
        + adversarial.get("attack_covered", 0) * 25
        + history.get("covered_refusals", 0) * 5
        - history.get("new_escalations", 0) * 100,
    )


def _base_disposition(
    loop_probe: dict[str, Any],
    assertion_summary: dict[str, Any],
    history: dict[str, Any],
    adversarial: dict[str, Any],
    config: DiscoveryConfig,
) -> tuple[CandidateDisposition, list[str]]:
    reasons: list[str] = []
    disposition = CandidateDisposition.PROPOSE
    if loop_probe.get("decision") == "BLOCK":
        disposition = CandidateDisposition.REJECT
        reasons.append("structural loop probe blocked the experiment window")
    elif loop_probe.get("decision") == "REVIEW":
        disposition = CandidateDisposition.REVIEW
        reasons.append("structural loop probe requires human review")
    if assertion_summary["failed"]:
        disposition = CandidateDisposition.REJECT
        reasons.append("one or more declared policy assertions failed")
    if history["candidate_errors"] or adversarial["candidate_errors"]:
        disposition = CandidateDisposition.REJECT
        reasons.append("candidate raised during deterministic evaluation")
    if history["new_escalations"] > config.max_new_blocks:
        disposition = CandidateDisposition.REJECT
        reasons.append(
            f"historical new-escalation count {history['new_escalations']} exceeds "
            f"acknowledged budget {config.max_new_blocks}"
        )
    if adversarial["benign_escalations"] > config.max_new_blocks:
        disposition = CandidateDisposition.REJECT
        reasons.append(
            f"adversarial benign-escalation count "
            f"{adversarial['benign_escalations']} exceeds acknowledged budget "
            f"{config.max_new_blocks}"
        )
    return disposition, reasons


def _apply_evidence_requirements(
    disposition: CandidateDisposition,
    reasons: list[str],
    assertions: list[dict[str, Any]],
    history: dict[str, Any],
    adversarial: dict[str, Any],
) -> CandidateDisposition:
    if history["state"] == "incomplete" and disposition is CandidateDisposition.PROPOSE:
        disposition = CandidateDisposition.REVIEW
        reasons.append("retained history lacks fields needed for complete replay")
    if (
        adversarial["state"] == "unavailable"
        and disposition is CandidateDisposition.PROPOSE
    ):
        disposition = CandidateDisposition.REVIEW
        reasons.append("no committed adversarial fixture was supplied")
    if not assertions and disposition is CandidateDisposition.PROPOSE:
        disposition = CandidateDisposition.REVIEW
        reasons.append("candidate declares no executable assertions")
    if disposition is CandidateDisposition.PROPOSE:
        reasons.append(
            "assertions, additive history replay, and adversarial replay passed"
        )
    return disposition


def _experiment(
    candidate: RuleCandidate,
    history_rows: list[dict[str, Any]],
    adversarial_rows: list[dict[str, Any]],
    config: DiscoveryConfig,
    loop_probe: dict[str, Any],
) -> tuple[CandidateExperiment, dict[str, Any] | None]:
    evidence_hashes = tuple(sorted(set(candidate.evidence.get("record_hashes", []))))
    candidate_digest = digest(candidate.to_dict())
    if candidate.kind != "policy":
        experiment = CandidateExperiment(
            candidate_id=candidate.id,
            kind=candidate.kind,
            severity=candidate.severity,
            capability=candidate.capability,
            support=candidate.support,
            candidate_digest=candidate_digest,
            policy_digest=None,
            evidence_record_hashes=evidence_hashes,
            assertions={"declared": 0, "passed": 0, "failed": 0, "failures": []},
            history={"state": "not_applicable"},
            adversarial={"state": "not_applicable"},
            disposition=CandidateDisposition.ADVISORY,
            priority_score=_priority(candidate, {}, {}),
            reasons=(
                "not expressible as an additive policy rule; human design required",
            ),
        )
        return experiment, None

    checker, assertions = _checker(candidate)
    assertion_summary = _assertion_summary(checker, assertions)
    history = _evaluate_additive(checker, history_rows, labeled=False)
    missing = _missing_history_evidence(candidate, history_rows)
    if missing:
        history["state"] = "incomplete"
        history["missing_evidence_records"] = len(missing)
        history["sample_missing_evidence_ids"] = list(missing[:10])
    adversarial = _evaluate_additive(checker, adversarial_rows, labeled=True)
    if not adversarial_rows:
        adversarial["state"] = "unavailable"

    disposition, reasons = _base_disposition(
        loop_probe, assertion_summary, history, adversarial, config
    )
    disposition = _apply_evidence_requirements(
        disposition, reasons, assertions, history, adversarial
    )

    policy_digest = digest(candidate.policy_document)
    experiment = CandidateExperiment(
        candidate_id=candidate.id,
        kind=candidate.kind,
        severity=candidate.severity,
        capability=candidate.capability,
        support=candidate.support,
        candidate_digest=candidate_digest,
        policy_digest=policy_digest,
        evidence_record_hashes=evidence_hashes,
        assertions=assertion_summary,
        history=history,
        adversarial=adversarial,
        disposition=disposition,
        priority_score=_priority(candidate, history, adversarial),
        reasons=tuple(reasons),
    )
    proposal = (
        candidate.policy_document
        if disposition is CandidateDisposition.PROPOSE
        else None
    )
    return experiment, proposal


def run_discovery(  # noqa: C901 - explicit experimental gate sequence
    decision_store: Any,
    replay_store: Any | None = None,
    *,
    adversarial_rows: list[dict[str, Any]] | None = None,
    loop_events: list[dict[str, object]] | None = None,
    validation_envelope: dict[str, Any] | None = None,
    config: DiscoveryConfig | None = None,
) -> DiscoveryResult:
    """Run one deterministic, proposal-only discovery cycle."""
    cfg = config or DiscoveryConfig()

    # Integrity is a precondition, not a score. load_graph validates every
    # record and execution anchor; verify_all catches chain discontinuity.
    graph = decision_store.load_graph()
    if not all(graph.verify_all().values()):
        raise DiscoveryInputError("sealed decision history failed chain verification")

    history_rows, replay_identity = _history_rows(
        decision_store, replay_store, cfg.since_ts
    )
    if len(history_rows) > cfg.max_history_records:
        raise DiscoveryInputError(
            f"history contains {len(history_rows)} decisions; limit is "
            f"{cfg.max_history_records}"
        )
    if len(adversarial_rows or []) > cfg.max_adversarial_rows:
        raise DiscoveryInputError(
            f"adversarial corpus contains {len(adversarial_rows or [])} rows; "
            f"limit is {cfg.max_adversarial_rows}"
        )
    adversarial = []
    for index, row in enumerate(adversarial_rows or []):
        adversarial.append(_validate_adversarial_row(row, f"adversarial_rows[{index}]"))
    ids = [row["id"] for row in adversarial]
    if len(ids) != len(set(ids)):
        raise DiscoveryInputError("adversarial rows contain duplicate ids")
    adversarial.sort(key=lambda row: row["id"])

    candidates = mine(
        decision_store,
        replay_store,
        since_ts=cfg.since_ts,
        min_support=cfg.min_support,
        numeric_field=cfg.numeric_field,
    )[: cfg.max_candidates]
    history_hashes = {row["record_hash"] for row in history_rows}
    for candidate in candidates:
        evidence_hashes = candidate.evidence.get("record_hashes")
        if not isinstance(evidence_hashes, list) or not evidence_hashes:
            raise DiscoveryInputError(
                f"candidate {candidate.id} has no sealed evidence record hashes"
            )
        if any(
            not isinstance(value, str) or not _RECORD_HASH.fullmatch(value)
            for value in evidence_hashes
        ):
            raise DiscoveryInputError(
                f"candidate {candidate.id} contains a malformed evidence hash"
            )
        if not set(evidence_hashes) <= history_hashes:
            raise DiscoveryInputError(
                f"candidate {candidate.id} cites evidence outside the verified window"
            )
    loop_probe = _loop_probe(loop_events)
    validation_probe = _validation_probe(validation_envelope, cfg.as_of)

    experiments: list[CandidateExperiment] = []
    proposals: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        experiment, proposal = _experiment(
            candidate, history_rows, adversarial, cfg, loop_probe
        )
        experiments.append(experiment)
        if proposal is not None:
            proposals[candidate.id] = proposal

    disposition_order = {
        CandidateDisposition.PROPOSE: 0,
        CandidateDisposition.REVIEW: 1,
        CandidateDisposition.REJECT: 2,
        CandidateDisposition.ADVISORY: 3,
    }
    experiments.sort(
        key=lambda item: (
            disposition_order[item.disposition],
            -item.priority_score,
            item.candidate_id,
        )
    )
    counts = {
        disposition.value: sum(item.disposition is disposition for item in experiments)
        for disposition in CandidateDisposition
    }
    if loop_probe.get("decision") == "BLOCK":
        status = DiscoveryStatus.STRUCTURAL_BLOCK
    elif counts[CandidateDisposition.PROPOSE.value]:
        status = DiscoveryStatus.PROPOSALS_READY
    elif experiments:
        status = DiscoveryStatus.REVIEW_REQUIRED
    else:
        status = DiscoveryStatus.NO_CHANGE

    input_identity = {
        "history": [
            {"decision_id": row["id"], "record_hash": row["record_hash"]}
            for row in history_rows
        ],
        "replay": replay_identity,
        "adversarial": adversarial,
        "loop_input_digest": loop_probe.get("input_digest"),
        "validation_report_hash": validation_probe.get("report_hash"),
        "candidates": [candidate.to_dict() for candidate in candidates],
    }
    body = {
        "spec": DISCOVERY_REPORT_SPEC,
        "configuration": asdict(cfg),
        "input_digest": digest(input_identity),
        "status": status.value,
        "source_counts": {
            "sealed_decisions": len(history_rows),
            "retained_inputs": len(replay_identity),
            "adversarial_rows": len(adversarial),
            "candidates": len(candidates),
        },
        "probes": {
            "agent_security_loops": loop_probe,
            "advisory_validation": validation_probe,
            "experimental_structural_probes": {
                "state": "QUARANTINED",
                "detail": (
                    "Hodge and authority-reachability outputs are not gating "
                    "until they have stable schemas and independent verifiers"
                ),
            },
        },
        "disposition_counts": counts,
        "experiments": [item.to_dict() for item in experiments],
        "claims": [
            "All candidates are proposals; none were applied.",
            "Counterfactuals use additive semantics and cannot relax existing levels.",
            "Priority score is a deterministic triage heuristic, not a validation metric.",
            "Wilson intervals describe the committed adversarial corpus only.",
            "Advisory-model validation never authorizes deterministic policy changes.",
        ],
    }
    envelope = {"body": body, "report_hash": digest(body)}
    return DiscoveryResult(envelope=envelope, proposal_documents=proposals)
