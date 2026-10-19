"""Which operations a capability may perform (ADR 0025).

A grant says an agent holds a capability, such as ``crm.read_contact``. On
its own that label says nothing about the request the permit will carry:
before this registry, an agent granted ``crm.read_contact`` could obtain a
permit for ``POST /api/v1/transfers`` on a payment service, and the receiver
admitted it (external review, 19 October 2026, finding 1). Every check
passed because each one only compared the caller's values with each other.

The operator now declares, per capability, the exact operations it covers::

    {
      "spec": "pv-operations/0.1",
      "operations": [
        {
          "operation_id": "pay-invoice-v1",
          "capability": "payments.pay_invoice",
          "transport": "https",
          "destination": "payments.partner.example",
          "operation": "POST /api/v1/transfers",
          "resource_prefix": "vendor:",
          "parameters_schema": {"type": "object", "required": ["amount"]}
        }
      ]
    }

Optional per entry: ``action`` (the execution action name; defaults to the
capability), ``credential_audience`` (defaults to the destination),
``wire_content_type``, and either ``resource_prefix`` or ``resources`` (an
exact list). ``parameters_schema`` is required: a JSON Schema the action's
parameters must satisfy. ``{"type": "object"}`` accepts any parameters, and
says so in the file.

A bound request matches an entry when every declared field is equal (the
operation is ``METHOD path``, compared exactly) and its parameters validate.
No entry for the capability, or no entry that matches, is a refusal. The
file is loaded once at start-up and refused there if malformed; its digest
is reported by ``GET /v1/runtime`` and with every permit.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import SchemaError  # type: ignore[import-untyped]

from agent_dna.advisory import Severity
from agent_dna.decision import Decision, DecisionResult

OPERATIONS_SPEC = "pv-operations/0.1"

OPERATION_NOT_DECLARED = "OPERATION_NOT_DECLARED"
OPERATION_MISMATCH = "OPERATION_MISMATCH"

_REQUIRED = ("operation_id", "capability", "transport", "destination", "operation")
_OPTIONAL = (
    "action",
    "credential_audience",
    "wire_content_type",
    "resource_prefix",
    "resources",
    "parameters_schema",
    "description",
)
_OPERATION = re.compile(r"^[A-Z]+ /\S*$")


class OperationRegistryError(ValueError):
    """The operations file is malformed; the server refuses to start."""


@dataclass(frozen=True)
class OperationRule:
    operation_id: str
    capability: str
    action: str
    transport: str
    destination: str
    credential_audience: str
    operation: str
    wire_content_type: str | None
    resource_prefix: str | None
    resources: frozenset[str] | None
    validator: Draft202012Validator

    def mismatch(
        self,
        execution_action: Mapping[str, Any],
        dispatch: Mapping[str, Any],
    ) -> str | None:
        """The first field that differs from this rule, or None on a match.

        ``dispatch`` may be a decide-time dispatch context, which carries no
        credential audience; that field is then checked at mint.
        """
        checks: list[tuple[str, Any, Any]] = [
            ("action", execution_action.get("action"), self.action),
            ("transport", dispatch.get("transport"), self.transport),
            ("destination", dispatch.get("destination"), self.destination),
            ("operation", dispatch.get("operation"), self.operation),
        ]
        if "credential_audience" in dispatch:
            checks.append(
                (
                    "credential_audience",
                    dispatch.get("credential_audience"),
                    self.credential_audience,
                )
            )
        if self.wire_content_type is not None:
            checks.append(
                (
                    "wire_content_type",
                    dispatch.get("wire_content_type"),
                    self.wire_content_type,
                )
            )
        for name, got, want in checks:
            if got != want:
                return f"{name} {got!r} is not {want!r}"
        resource = execution_action.get("resource")
        if self.resources is not None and resource not in self.resources:
            return f"resource {resource!r} is not declared"
        if self.resource_prefix is not None and not (
            isinstance(resource, str) and resource.startswith(self.resource_prefix)
        ):
            return f"resource {resource!r} is outside {self.resource_prefix!r}"
        errors = sorted(
            self.validator.iter_errors(execution_action.get("parameters")),
            key=lambda e: list(e.path),
        )
        if errors:
            where = "/".join(str(p) for p in errors[0].path) or "parameters"
            return f"parameters do not match the declared schema ({where}: {errors[0].message})"
        return None


@dataclass(frozen=True)
class OperationMatch:
    ok: bool
    reason_code: str | None = None
    detail: str = ""
    operation_id: str | None = None


TRIGGERED_BY_OPERATION = "operation_registry"


def operation_block(
    capability: str, agent_id: str, match: OperationMatch
) -> DecisionResult:
    """The sealed BLOCK for a request its capability does not declare."""
    return DecisionResult(
        decision=Decision.BLOCK,
        triggered_by=TRIGGERED_BY_OPERATION,
        reason=f"{match.reason_code}: {match.detail}",
        capability=capability,
        agent_id=agent_id,
        drift_score=0.0,
        severity=Severity.CRITICAL,
    )


class OperationRegistry:
    def __init__(self, rules: list[OperationRule], digest: str) -> None:
        self._by_capability: dict[str, list[OperationRule]] = {}
        for rule in rules:
            self._by_capability.setdefault(rule.capability, []).append(rule)
        self.digest = digest
        self.size = len(rules)

    def check(
        self,
        capability: str,
        execution_action: Mapping[str, Any],
        dispatch: Mapping[str, Any],
    ) -> OperationMatch:
        rules = self._by_capability.get(capability, [])
        if not rules:
            return OperationMatch(
                False,
                OPERATION_NOT_DECLARED,
                f"no operation is declared for capability {capability!r}",
            )
        reasons = []
        for rule in rules:
            why = rule.mismatch(execution_action, dispatch)
            if why is None:
                return OperationMatch(True, operation_id=rule.operation_id)
            reasons.append(f"{rule.operation_id}: {why}")
        return OperationMatch(
            False,
            OPERATION_MISMATCH,
            f"capability {capability!r} does not cover this request ("
            + "; ".join(reasons)
            + ")",
        )


def _text(entry: Mapping[str, Any], key: str, where: str) -> str:
    value = entry.get(key)
    if not isinstance(value, str) or not value:
        raise OperationRegistryError(f"{where}: {key} must be a non-empty string")
    return value


def _rule(entry: Any, where: str) -> OperationRule:
    if not isinstance(entry, Mapping):
        raise OperationRegistryError(f"{where}: must be an object")
    unknown = set(entry) - set(_REQUIRED) - set(_OPTIONAL)
    if unknown:
        raise OperationRegistryError(f"{where}: unknown fields {sorted(unknown)}")
    fields = {key: _text(entry, key, where) for key in _REQUIRED}
    if not _OPERATION.match(fields["operation"]):
        raise OperationRegistryError(f"{where}: operation must be 'METHOD /path'")
    if "parameters_schema" not in entry:
        raise OperationRegistryError(
            f'{where}: parameters_schema is required ({{"type": "object"}} accepts any)'
        )
    schema = entry["parameters_schema"]
    if not isinstance(schema, Mapping):
        raise OperationRegistryError(f"{where}: parameters_schema must be an object")
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        raise OperationRegistryError(
            f"{where}: parameters_schema: {exc.message}"
        ) from exc
    if "resource_prefix" in entry and "resources" in entry:
        raise OperationRegistryError(
            f"{where}: give resource_prefix or resources, not both"
        )
    resources = entry.get("resources")
    if resources is not None and (
        not isinstance(resources, list)
        or not resources
        or not all(isinstance(r, str) and r for r in resources)
    ):
        raise OperationRegistryError(
            f"{where}: resources must be a non-empty list of strings"
        )
    optional = {
        key: _text(entry, key, where)
        for key in (
            "action",
            "credential_audience",
            "wire_content_type",
            "resource_prefix",
        )
        if key in entry
    }
    return OperationRule(
        operation_id=fields["operation_id"],
        capability=fields["capability"],
        action=optional.get("action", fields["capability"]),
        transport=fields["transport"],
        destination=fields["destination"],
        credential_audience=optional.get("credential_audience", fields["destination"]),
        operation=fields["operation"],
        wire_content_type=optional.get("wire_content_type"),
        resource_prefix=optional.get("resource_prefix"),
        resources=frozenset(resources) if resources is not None else None,
        validator=Draft202012Validator(dict(schema)),
    )


def parse_operation_registry(document: Any) -> OperationRegistry:
    if not isinstance(document, Mapping) or document.get("spec") != OPERATIONS_SPEC:
        raise OperationRegistryError(f"spec must be {OPERATIONS_SPEC!r}")
    if set(document) - {"spec", "operations"}:
        raise OperationRegistryError(
            "only spec and operations are allowed at the top level"
        )
    entries = document.get("operations")
    if not isinstance(entries, list):
        raise OperationRegistryError("operations must be a list")
    rules = [_rule(entry, f"operations[{i}]") for i, entry in enumerate(entries)]
    ids = [r.operation_id for r in rules]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    if duplicates:
        raise OperationRegistryError(f"duplicate operation_id {duplicates}")
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
    digest = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return OperationRegistry(rules, digest)


def load_operation_registry(path: str | Path) -> OperationRegistry:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OperationRegistryError(f"cannot read {path}: {exc}") from exc
    return parse_operation_registry(document)
