#!/usr/bin/env python3
"""Independent standard-library verifier for pv-discovery-loop-report/1.0."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path
from typing import Any

SPEC = "pv-discovery-loop-report/1.0"
DISPOSITIONS = ("PROPOSE", "REVIEW", "REJECT", "ADVISORY")
ORDER = {name: index for index, name in enumerate(DISPOSITIONS)}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
RECORD_HASH = re.compile(r"^[0-9a-f]{64}$")


class VerificationError(ValueError):
    pass


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise VerificationError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _constant(token: str) -> None:
    raise VerificationError(f"non-finite JSON number: {token}")


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _exact(value: dict[str, Any], fields: set[str], path: str) -> None:
    if set(value) != fields:
        raise VerificationError(
            f"{path}: fields must be exactly {sorted(fields)}, got {sorted(value)}"
        )


def _integer(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise VerificationError(f"{path}: expected non-negative integer")
    return value


def _verify_assertions(value: Any, path: str) -> None:
    if not isinstance(value, dict):
        raise VerificationError(f"{path}: expected object")
    _exact(value, {"declared", "passed", "failed", "failures"}, path)
    declared = _integer(value["declared"], f"{path}.declared")
    passed = _integer(value["passed"], f"{path}.passed")
    failed = _integer(value["failed"], f"{path}.failed")
    failures = value["failures"]
    if declared != passed + failed:
        raise VerificationError(f"{path}: declared count is inconsistent")
    if not isinstance(failures, list) or len(failures) != failed:
        raise VerificationError(f"{path}.failures: count is inconsistent")
    for index, failure in enumerate(failures):
        if not isinstance(failure, dict):
            raise VerificationError(f"{path}.failures[{index}]: expected object")
        _exact(failure, {"name", "expected", "actual"}, f"{path}.failures[{index}]")


def _verify_ids(value: Any, path: str) -> None:
    if not isinstance(value, list) or len(value) > 10:
        raise VerificationError(f"{path}: expected at most 10 ids")
    if any(not isinstance(item, str) or not item for item in value):
        raise VerificationError(f"{path}: expected non-empty string ids")


def _verify_interval(value: Any, total: int, path: str) -> None:
    if total == 0:
        if value is not None:
            raise VerificationError(f"{path}: expected null for an empty sample")
        return
    if (
        not isinstance(value, list)
        or len(value) != 2
        or any(
            isinstance(item, bool) or not isinstance(item, (int, float))
            for item in value
        )
        or not 0 <= value[0] <= value[1] <= 1
    ):
        raise VerificationError(f"{path}: invalid [lower, upper] interval")


def _verify_evaluation(  # noqa: C901 - independent summary validation
    value: Any, path: str, *, labeled: bool
) -> None:
    if not isinstance(value, dict):
        raise VerificationError(f"{path}: expected object")
    if value == {"state": "not_applicable"}:
        return
    base = {
        "state",
        "evaluated",
        "new_escalations",
        "covered_refusals",
        "benign_escalations",
        "candidate_errors",
        "sample_new_escalation_ids",
        "sample_covered_refusal_ids",
        "sample_benign_escalation_ids",
        "error_ids",
        "attack_rows",
        "attack_covered",
        "attack_coverage_wilson_95",
        "benign_rows",
        "benign_preserved",
        "benign_preservation_wilson_95",
        "semantics",
    }
    state = value.get("state")
    expected = base | (
        {"missing_evidence_records", "sample_missing_evidence_ids"}
        if state == "incomplete"
        else set()
    )
    _exact(value, expected, path)
    if state not in {"complete", "incomplete", "unavailable"}:
        raise VerificationError(f"{path}.state: unsupported value")
    if value["semantics"] != "additive_candidate_never_relaxes_existing_levels":
        raise VerificationError(f"{path}.semantics: unsupported value")
    integer_fields = (
        "evaluated",
        "new_escalations",
        "covered_refusals",
        "benign_escalations",
        "candidate_errors",
        "attack_rows",
        "attack_covered",
        "benign_rows",
        "benign_preserved",
    )
    numbers = {
        field: _integer(value[field], f"{path}.{field}") for field in integer_fields
    }
    for field in (
        "sample_new_escalation_ids",
        "sample_covered_refusal_ids",
        "sample_benign_escalation_ids",
        "error_ids",
    ):
        _verify_ids(value[field], f"{path}.{field}")
    if numbers["new_escalations"] + numbers["covered_refusals"] > (
        numbers["evaluated"] - numbers["candidate_errors"]
    ):
        raise VerificationError(f"{path}: fired counts exceed successful evaluations")
    if numbers["benign_escalations"] > numbers["new_escalations"]:
        raise VerificationError(f"{path}: benign escalations exceed all escalations")
    if numbers["attack_covered"] > numbers["attack_rows"]:
        raise VerificationError(f"{path}: attack coverage count is impossible")
    if numbers["benign_preserved"] > numbers["benign_rows"]:
        raise VerificationError(f"{path}: benign preservation count is impossible")
    if labeled:
        if numbers["attack_rows"] + numbers["benign_rows"] != numbers["evaluated"]:
            raise VerificationError(f"{path}: label counts do not match evaluations")
    elif numbers["attack_rows"] or numbers["benign_rows"]:
        raise VerificationError(f"{path}: unlabeled history contains label counts")
    _verify_interval(
        value["attack_coverage_wilson_95"],
        numbers["attack_rows"],
        f"{path}.attack_coverage_wilson_95",
    )
    _verify_interval(
        value["benign_preservation_wilson_95"],
        numbers["benign_rows"],
        f"{path}.benign_preservation_wilson_95",
    )
    if state == "unavailable" and numbers["evaluated"]:
        raise VerificationError(f"{path}: unavailable evaluation is not empty")
    if state == "incomplete":
        missing = _integer(
            value["missing_evidence_records"], f"{path}.missing_evidence_records"
        )
        if missing < 1:
            raise VerificationError(f"{path}.missing_evidence_records: expected >= 1")
        _verify_ids(
            value["sample_missing_evidence_ids"], f"{path}.sample_missing_evidence_ids"
        )


def _verify_experiment(  # noqa: C901 - independent contract validation
    item: Any, index: int
) -> tuple[str, int, str]:
    path = f"body.experiments[{index}]"
    if not isinstance(item, dict):
        raise VerificationError(f"{path}: expected object")
    _exact(
        item,
        {
            "candidate_id",
            "kind",
            "severity",
            "capability",
            "support",
            "candidate_digest",
            "policy_digest",
            "evidence_record_hashes",
            "assertions",
            "history",
            "adversarial",
            "disposition",
            "priority_score",
            "reasons",
        },
        path,
    )
    disposition = item["disposition"]
    if disposition not in DISPOSITIONS:
        raise VerificationError(f"{path}.disposition: unsupported value")
    for field in ("candidate_id", "kind", "severity", "capability"):
        if not isinstance(item[field], str) or not item[field]:
            raise VerificationError(f"{path}.{field}: expected non-empty string")
    if item["kind"] not in {"policy", "grant", "advisory"}:
        raise VerificationError(f"{path}.kind: unsupported value")
    if item["severity"] not in {"HIGH", "MEDIUM"}:
        raise VerificationError(f"{path}.severity: unsupported value")
    for field in ("support", "priority_score"):
        _integer(item[field], f"{path}.{field}")
    if not DIGEST.fullmatch(str(item["candidate_digest"])):
        raise VerificationError(f"{path}.candidate_digest: invalid digest")
    policy_digest = item["policy_digest"]
    if policy_digest is not None and not DIGEST.fullmatch(str(policy_digest)):
        raise VerificationError(f"{path}.policy_digest: invalid digest")
    hashes = item["evidence_record_hashes"]
    if not isinstance(hashes, list) or hashes != sorted(set(hashes)):
        raise VerificationError(f"{path}.evidence_record_hashes: not sorted unique")
    if any(
        not isinstance(value, str) or not RECORD_HASH.fullmatch(value)
        for value in hashes
    ):
        raise VerificationError(f"{path}.evidence_record_hashes: invalid record hash")
    reasons = item["reasons"]
    if not isinstance(reasons, list) or any(
        not isinstance(reason, str) or not reason for reason in reasons
    ):
        raise VerificationError(f"{path}.reasons: expected non-empty strings")

    assertions = item["assertions"]
    history = item["history"]
    adversarial = item["adversarial"]
    _verify_assertions(assertions, f"{path}.assertions")
    _verify_evaluation(history, f"{path}.history", labeled=False)
    _verify_evaluation(adversarial, f"{path}.adversarial", labeled=True)
    if item["kind"] == "policy" and (
        history == {"state": "not_applicable"}
        or adversarial == {"state": "not_applicable"}
    ):
        raise VerificationError(f"{path}: policy experiment cannot be not_applicable")
    if item["kind"] != "policy" and (
        history != {"state": "not_applicable"}
        or adversarial != {"state": "not_applicable"}
    ):
        raise VerificationError(f"{path}: non-policy experiment must be advisory-only")
    if (item["kind"] == "policy") == (disposition == "ADVISORY"):
        raise VerificationError(
            f"{path}: disposition is inconsistent with candidate kind"
        )
    if disposition == "PROPOSE":
        if item["kind"] != "policy" or policy_digest is None:
            raise VerificationError(f"{path}: PROPOSE must identify a policy digest")
        if assertions.get("failed") != 0 or assertions.get("declared", 0) < 1:
            raise VerificationError(f"{path}: PROPOSE has failed or absent assertions")
        if history.get("state") != "complete" or adversarial.get("state") != "complete":
            raise VerificationError(
                f"{path}: PROPOSE requires complete replay evidence"
            )
        if history.get("candidate_errors") or adversarial.get("candidate_errors"):
            raise VerificationError(f"{path}: PROPOSE contains candidate errors")
    return disposition, item["priority_score"], item["candidate_id"]


def verify(envelope: Any) -> dict[str, Any]:  # noqa: C901 - independent verifier
    if not isinstance(envelope, dict):
        raise VerificationError("root: expected object")
    _exact(envelope, {"body", "report_hash"}, "root")
    body = envelope["body"]
    if not isinstance(body, dict):
        raise VerificationError("body: expected object")
    _exact(
        body,
        {
            "spec",
            "configuration",
            "input_digest",
            "status",
            "source_counts",
            "probes",
            "disposition_counts",
            "experiments",
            "claims",
        },
        "body",
    )
    if body["spec"] != SPEC:
        raise VerificationError(f"body.spec: expected {SPEC}")
    if not DIGEST.fullmatch(str(envelope["report_hash"])):
        raise VerificationError("report_hash: invalid digest")
    if envelope["report_hash"] != _digest(body):
        raise VerificationError("report_hash: digest mismatch")
    if not DIGEST.fullmatch(str(body["input_digest"])):
        raise VerificationError("body.input_digest: invalid digest")

    configuration = body["configuration"]
    if not isinstance(configuration, dict):
        raise VerificationError("body.configuration: expected object")
    _exact(
        configuration,
        {
            "min_support",
            "numeric_field",
            "since_ts",
            "max_new_blocks",
            "max_candidates",
            "max_history_records",
            "max_adversarial_rows",
            "as_of",
        },
        "body.configuration",
    )
    budget = _integer(configuration["max_new_blocks"], "configuration.max_new_blocks")
    for field in (
        "min_support",
        "max_candidates",
        "max_history_records",
        "max_adversarial_rows",
    ):
        if _integer(configuration[field], f"configuration.{field}") < 1:
            raise VerificationError(f"configuration.{field}: expected >= 1")
    if not isinstance(configuration["numeric_field"], str) or not (
        1 <= len(configuration["numeric_field"]) <= 128
    ):
        raise VerificationError("configuration.numeric_field: invalid value")
    for field in ("since_ts", "as_of"):
        value = configuration[field]
        if value is None and field == "since_ts":
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            raise VerificationError(f"configuration.{field}: invalid timestamp")

    experiments = body["experiments"]
    if not isinstance(experiments, list):
        raise VerificationError("body.experiments: expected array")
    keys = [_verify_experiment(item, index) for index, item in enumerate(experiments)]
    candidate_ids = [key[2] for key in keys]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise VerificationError("body.experiments: duplicate candidate ids")
    for index, item in enumerate(experiments):
        if item["disposition"] != "PROPOSE":
            continue
        if item["history"].get("new_escalations", budget + 1) > budget:
            raise VerificationError(
                f"body.experiments[{index}]: historical budget exceeded"
            )
        if item["adversarial"].get("benign_escalations", budget + 1) > budget:
            raise VerificationError(
                f"body.experiments[{index}]: adversarial benign budget exceeded"
            )
    expected_keys = sorted(keys, key=lambda key: (ORDER[key[0]], -key[1], key[2]))
    if keys != expected_keys:
        raise VerificationError("body.experiments: non-deterministic order")

    counts = body["disposition_counts"]
    if not isinstance(counts, dict):
        raise VerificationError("body.disposition_counts: expected object")
    _exact(counts, set(DISPOSITIONS), "body.disposition_counts")
    actual = {name: sum(key[0] == name for key in keys) for name in DISPOSITIONS}
    if counts != actual:
        raise VerificationError("body.disposition_counts: does not match experiments")

    source_counts = body["source_counts"]
    if not isinstance(source_counts, dict):
        raise VerificationError("body.source_counts: expected object")
    _exact(
        source_counts,
        {"sealed_decisions", "retained_inputs", "adversarial_rows", "candidates"},
        "body.source_counts",
    )
    for field, value in source_counts.items():
        _integer(value, f"body.source_counts.{field}")
    if source_counts["candidates"] != len(experiments):
        raise VerificationError("candidate count does not match experiments")
    if source_counts["candidates"] > configuration["max_candidates"]:
        raise VerificationError("candidate count exceeds configured bound")
    if source_counts["sealed_decisions"] > configuration["max_history_records"]:
        raise VerificationError("history count exceeds configured bound")
    if source_counts["adversarial_rows"] > configuration["max_adversarial_rows"]:
        raise VerificationError("adversarial count exceeds configured bound")

    probes = body["probes"]
    if not isinstance(probes, dict):
        raise VerificationError("body.probes: expected object")
    _exact(
        probes,
        {
            "agent_security_loops",
            "advisory_validation",
            "experimental_structural_probes",
        },
        "body.probes",
    )
    loop = probes.get("agent_security_loops")
    if not isinstance(loop, dict):
        raise VerificationError("agent-security loop probe is missing")
    if loop.get("state") == "ABSENT":
        _exact(loop, {"state", "effect"}, "body.probes.agent_security_loops")
    elif loop.get("state") == "VERIFIED":
        _exact(
            loop,
            {
                "state",
                "decision",
                "report_id",
                "input_digest",
                "findings",
                "reason_codes",
                "effect",
            },
            "body.probes.agent_security_loops",
        )
        if loop.get("decision") not in {"ALLOW", "REVIEW", "BLOCK"}:
            raise VerificationError("agent-security loop decision is invalid")
        if not DIGEST.fullmatch(str(loop.get("input_digest"))):
            raise VerificationError("agent-security loop input digest is invalid")
        if not DIGEST.fullmatch(str(loop.get("report_id"))):
            raise VerificationError("agent-security loop report id is invalid")
        _integer(loop.get("findings"), "body.probes.agent_security_loops.findings")
        if not isinstance(loop.get("reason_codes"), list):
            raise VerificationError("agent-security loop reason codes are invalid")
    else:
        raise VerificationError("agent-security loop state is invalid")

    validation = probes["advisory_validation"]
    if not isinstance(validation, dict) or validation.get("state") not in {
        "ABSENT",
        "VERIFIED",
        "EXPIRED",
        "INVALID",
    }:
        raise VerificationError("advisory validation probe is invalid")
    if validation["state"] == "ABSENT":
        _exact(validation, {"state", "effect"}, "advisory validation probe")
    elif validation["state"] == "INVALID":
        _exact(
            validation,
            {"state", "reason", "effect"},
            "advisory validation probe",
        )
    else:
        _exact(
            validation,
            {"state", "report_hash", "score_name", "score_type", "auc", "effect"},
            "advisory validation probe",
        )
        if not re.fullmatch(r"[0-9a-f]{64}", str(validation["report_hash"])):
            raise VerificationError("advisory validation report hash is invalid")
    experimental = probes["experimental_structural_probes"]
    if not isinstance(experimental, dict):
        raise VerificationError("experimental structural probe is invalid")
    _exact(experimental, {"state", "detail"}, "experimental structural probe")
    if experimental["state"] != "QUARANTINED":
        raise VerificationError("experimental structural probes are not quarantined")
    if loop.get("decision") in {"BLOCK", "REVIEW"} and counts["PROPOSE"]:
        raise VerificationError("structural BLOCK/REVIEW cannot emit PROPOSE")

    status = body["status"]
    expected_status = (
        "STRUCTURAL_BLOCK"
        if loop.get("decision") == "BLOCK"
        else "PROPOSALS_READY"
        if counts["PROPOSE"]
        else "REVIEW_REQUIRED"
        if experiments
        else "NO_CHANGE"
    )
    if status != expected_status:
        raise VerificationError(f"body.status: expected {expected_status}")
    claims = body["claims"]
    if not isinstance(claims, list) or not any(
        isinstance(claim, str) and "none were applied" in claim.lower()
        for claim in claims
    ):
        raise VerificationError("body.claims: proposal-only claim is missing")

    # Walk all numeric values once; bool is not a numeric measurement here.
    stack = [envelope]
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            stack.extend(value.values())
        elif isinstance(value, list):
            stack.extend(value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise VerificationError("report contains a non-finite number")
    return {
        "ok": True,
        "spec": SPEC,
        "report_hash": envelope["report_hash"],
        "status": status,
        "experiments": len(experiments),
    }


def _load(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object,
            parse_constant=_constant,
        )
    except OSError as exc:
        raise VerificationError(f"cannot read {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise VerificationError(f"invalid JSON: {exc}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify(_load(args.report))
    except (VerificationError, TypeError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        f"PASS {result['spec']} {result['status']} "
        f"experiments={result['experiments']} {result['report_hash']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
